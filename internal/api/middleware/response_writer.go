// Package middleware 提供 CLI Proxy API 的 Gin HTTP 中间件，含可采集并记录请求/响应（含流式）的 ResponseWriter 封装，不增加延迟。
package middleware

import (
	"bytes"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/logging"
)

// RequestInfo 保存入站 HTTP 请求的关键信息，用于日志。
type RequestInfo struct {
	URL       string              // 请求 URL
	Method    string              // HTTP 方法（如 GET、POST）
	Headers   map[string][]string // 请求头
	Body      []byte              // 原始请求体
	RequestID string              // 请求唯一标识
	Timestamp time.Time           // 请求接收时间
}

// ResponseWriterWrapper 封装 gin.ResponseWriter，拦截并记录响应；支持普通与流式响应，日志不阻塞客户端。
type ResponseWriterWrapper struct {
	gin.ResponseWriter
	body                *bytes.Buffer              // 非流式响应的体缓冲
	isStreaming         bool                       // 是否为流式（如 text/event-stream）
	streamWriter        logging.StreamingLogWriter // 流式日志写入器
	chunkChannel        chan []byte                // 异步向日志传递响应块的通道
	streamDone          chan struct{}              // 流式 goroutine 完成信号
	logger              logging.RequestLogger      // 请求日志服务实例
	requestInfo         *RequestInfo               // 原始请求信息
	statusCode          int                        // 响应状态码
	headers             map[string][]string        // 响应头
	logOnErrorOnly      bool                       // 仅在有错误响应时记录
	firstChunkTimestamp time.Time                  // 流式首包时间（TTFB）
}

// NewResponseWriterWrapper 创建并初始化 ResponseWriterWrapper，需传入原始 ResponseWriter、日志实例与已采集的请求信息。
func NewResponseWriterWrapper(w gin.ResponseWriter, logger logging.RequestLogger, requestInfo *RequestInfo) *ResponseWriterWrapper {
	return &ResponseWriterWrapper{
		ResponseWriter: w,
		body:           &bytes.Buffer{},
		logger:         logger,
		requestInfo:    requestInfo,
		headers:        make(map[string][]string),
	}
}

// Write 封装底层 Write，先写客户端再处理日志；非流式写入内部缓冲，流式通过非阻塞通道异步记录。
func (w *ResponseWriterWrapper) Write(data []byte) (int, error) {
	w.ensureHeadersCaptured()

	n, err := w.ResponseWriter.Write(data)

	if w.isStreaming && w.chunkChannel != nil {
		if w.firstChunkTimestamp.IsZero() {
			w.firstChunkTimestamp = time.Now()
		}
		select {
		case w.chunkChannel <- append([]byte(nil), data...):
		default:
		}
		return n, err
	}

	if w.shouldBufferResponseBody() {
		w.body.Write(data)
	}

	return n, err
}

func (w *ResponseWriterWrapper) shouldBufferResponseBody() bool {
	if w.logger != nil && w.logger.IsEnabled() {
		return true
	}
	if !w.logOnErrorOnly {
		return false
	}
	status := w.statusCode
	if status == 0 {
		if statusWriter, ok := w.ResponseWriter.(interface{ Status() int }); ok && statusWriter != nil {
			status = statusWriter.Status()
		} else {
			status = http.StatusOK
		}
	}
	return status >= http.StatusBadRequest
}

// WriteString 封装 WriteString 以采集数据；部分处理器通过 io.StringWriter 写入，不重写则不会进入请求日志。
func (w *ResponseWriterWrapper) WriteString(data string) (int, error) {
	w.ensureHeadersCaptured()

	n, err := w.ResponseWriter.WriteString(data)

	if w.isStreaming && w.chunkChannel != nil {
		if w.firstChunkTimestamp.IsZero() {
			w.firstChunkTimestamp = time.Now()
		}
		select {
		case w.chunkChannel <- []byte(data):
		default:
		}
		return n, err
	}

	if w.shouldBufferResponseBody() {
		w.body.WriteString(data)
	}
	return n, err
}

// WriteHeader 封装底层 WriteHeader：记录状态码、按 Content-Type 判断是否流式并初始化对应日志（标准或流式）。
func (w *ResponseWriterWrapper) WriteHeader(statusCode int) {
	w.statusCode = statusCode

	w.captureCurrentHeaders()

	contentType := w.ResponseWriter.Header().Get("Content-Type")
	w.isStreaming = w.detectStreaming(contentType)

	if w.isStreaming && w.logger.IsEnabled() {
		streamWriter, err := w.logger.LogStreamingRequest(
			w.requestInfo.URL,
			w.requestInfo.Method,
			w.requestInfo.Headers,
			w.requestInfo.Body,
			w.requestInfo.RequestID,
		)
		if err == nil {
			w.streamWriter = streamWriter
			w.chunkChannel = make(chan []byte, 100)
			doneChan := make(chan struct{})
			w.streamDone = doneChan

			go w.processStreamingChunks(doneChan)

			_ = streamWriter.WriteStatus(statusCode, w.headers)
		}
	}

	w.ResponseWriter.WriteHeader(statusCode)
}

// ensureHeadersCaptured 确保已采集响应头，可多次调用，每次会从底层 ResponseWriter 刷新最新状态。
func (w *ResponseWriterWrapper) ensureHeadersCaptured() {
	w.captureCurrentHeaders()
}

// captureCurrentHeaders 从底层 ResponseWriter 读取所有头并存入封装体的 headers，复制值以避免竞态。
func (w *ResponseWriterWrapper) captureCurrentHeaders() {
	if w.headers == nil {
		w.headers = make(map[string][]string)
	}

	for key, values := range w.ResponseWriter.Header() {
		headerValues := make([]string, len(values))
		copy(headerValues, values)
		w.headers[key] = headerValues
	}
}

// detectStreaming 判断是否为流式响应：Content-Type 含 text/event-stream，或请求体含 "stream": true。
func (w *ResponseWriterWrapper) detectStreaming(contentType string) bool {
	if strings.Contains(contentType, "text/event-stream") {
		return true
	}

	if strings.TrimSpace(contentType) != "" {
		return false
	}

	if w.requestInfo != nil && len(w.requestInfo.Body) > 0 {
		bodyStr := string(w.requestInfo.Body)
		return strings.Contains(bodyStr, `"stream": true`) || strings.Contains(bodyStr, `"stream":true`)
	}

	return false
}

// processStreamingChunks 在独立 goroutine 中从 chunkChannel 读取块并异步写入流式日志。
func (w *ResponseWriterWrapper) processStreamingChunks(done chan struct{}) {
	if done == nil {
		return
	}

	defer close(done)

	if w.streamWriter == nil || w.chunkChannel == nil {
		return
	}

	for chunk := range w.chunkChannel {
		w.streamWriter.WriteChunkAsync(chunk)
	}
}

// Finalize 完成请求与响应的日志：流式时关闭 chunk 通道与流式写入器；非流式时记录完整请求/响应及 Gin 上下文中的 API 数据。
func (w *ResponseWriterWrapper) Finalize(c *gin.Context) error {
	if w.logger == nil {
		return nil
	}

	finalStatusCode := w.statusCode
	if finalStatusCode == 0 {
		if statusWriter, ok := w.ResponseWriter.(interface{ Status() int }); ok {
			finalStatusCode = statusWriter.Status()
		} else {
			finalStatusCode = 200
		}
	}

	var slicesAPIResponseError []*interfaces.ErrorMessage
	apiResponseError, isExist := c.Get("API_RESPONSE_ERROR")
	if isExist {
		if apiErrors, ok := apiResponseError.([]*interfaces.ErrorMessage); ok {
			slicesAPIResponseError = apiErrors
		}
	}

	hasAPIError := len(slicesAPIResponseError) > 0 || finalStatusCode >= http.StatusBadRequest
	forceLog := w.logOnErrorOnly && hasAPIError && !w.logger.IsEnabled()
	if !w.logger.IsEnabled() && !forceLog {
		return nil
	}

	if w.isStreaming && w.streamWriter != nil {
		if w.chunkChannel != nil {
			close(w.chunkChannel)
			w.chunkChannel = nil
		}

		if w.streamDone != nil {
			<-w.streamDone
			w.streamDone = nil
		}

		w.streamWriter.SetFirstChunkTimestamp(w.firstChunkTimestamp)

		apiRequest := w.extractAPIRequest(c)
		if len(apiRequest) > 0 {
			_ = w.streamWriter.WriteAPIRequest(apiRequest)
		}
		apiResponse := w.extractAPIResponse(c)
		if len(apiResponse) > 0 {
			_ = w.streamWriter.WriteAPIResponse(apiResponse)
		}
		if err := w.streamWriter.Close(); err != nil {
			w.streamWriter = nil
			return err
		}
		w.streamWriter = nil
		return nil
	}

	return w.logRequest(finalStatusCode, w.cloneHeaders(), w.body.Bytes(), w.extractAPIRequest(c), w.extractAPIResponse(c), w.extractAPIResponseTimestamp(c), slicesAPIResponseError, forceLog)
}

func (w *ResponseWriterWrapper) cloneHeaders() map[string][]string {
	w.ensureHeadersCaptured()

	finalHeaders := make(map[string][]string, len(w.headers))
	for key, values := range w.headers {
		headerValues := make([]string, len(values))
		copy(headerValues, values)
		finalHeaders[key] = headerValues
	}

	return finalHeaders
}

func (w *ResponseWriterWrapper) extractAPIRequest(c *gin.Context) []byte {
	apiRequest, isExist := c.Get("API_REQUEST")
	if !isExist {
		return nil
	}
	data, ok := apiRequest.([]byte)
	if !ok || len(data) == 0 {
		return nil
	}
	return data
}

func (w *ResponseWriterWrapper) extractAPIResponse(c *gin.Context) []byte {
	apiResponse, isExist := c.Get("API_RESPONSE")
	if !isExist {
		return nil
	}
	data, ok := apiResponse.([]byte)
	if !ok || len(data) == 0 {
		return nil
	}
	return data
}

func (w *ResponseWriterWrapper) extractAPIResponseTimestamp(c *gin.Context) time.Time {
	ts, isExist := c.Get("API_RESPONSE_TIMESTAMP")
	if !isExist {
		return time.Time{}
	}
	if t, ok := ts.(time.Time); ok {
		return t
	}
	return time.Time{}
}

func (w *ResponseWriterWrapper) logRequest(statusCode int, headers map[string][]string, body []byte, apiRequestBody, apiResponseBody []byte, apiResponseTimestamp time.Time, apiResponseErrors []*interfaces.ErrorMessage, forceLog bool) error {
	if w.requestInfo == nil {
		return nil
	}

	var requestBody []byte
	if len(w.requestInfo.Body) > 0 {
		requestBody = w.requestInfo.Body
	}

	if loggerWithOptions, ok := w.logger.(interface {
		LogRequestWithOptions(string, string, map[string][]string, []byte, int, map[string][]string, []byte, []byte, []byte, []*interfaces.ErrorMessage, bool, string, time.Time, time.Time) error
	}); ok {
		return loggerWithOptions.LogRequestWithOptions(
			w.requestInfo.URL,
			w.requestInfo.Method,
			w.requestInfo.Headers,
			requestBody,
			statusCode,
			headers,
			body,
			apiRequestBody,
			apiResponseBody,
			apiResponseErrors,
			forceLog,
			w.requestInfo.RequestID,
			w.requestInfo.Timestamp,
			apiResponseTimestamp,
		)
	}

	return w.logger.LogRequest(
		w.requestInfo.URL,
		w.requestInfo.Method,
		w.requestInfo.Headers,
		requestBody,
		statusCode,
		headers,
		body,
		apiRequestBody,
		apiResponseBody,
		apiResponseErrors,
		w.requestInfo.RequestID,
		w.requestInfo.Timestamp,
		apiResponseTimestamp,
	)
}
