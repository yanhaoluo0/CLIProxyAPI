// Package middleware 提供 CLI Proxy API 的 HTTP 中间件。
// 本文件为请求日志中间件，在配置启用时记录请求与响应的完整数据。
package middleware

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
)

// RequestLoggingMiddleware 返回记录 HTTP 请求与响应的 Gin 中间件，通过 RequestLogger 记录头与体等详情；日志关闭时仍会采集数据以便持久化上游错误。
func RequestLoggingMiddleware(logger logging.RequestLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if logger == nil {
			c.Next()
			return
		}

		if c.Request.Method == http.MethodGet {
			c.Next()
			return
		}

		path := c.Request.URL.Path
		if !shouldLogRequest(path) {
			c.Next()
			return
		}

		requestInfo, err := captureRequestInfo(c)
		if err != nil {
			c.Next()
			return
		}

		wrapper := NewResponseWriterWrapper(c.Writer, logger, requestInfo)
		if !logger.IsEnabled() {
			wrapper.logOnErrorOnly = true
		}
		c.Writer = wrapper

		c.Next()

		if err = wrapper.Finalize(c); err != nil {
			// 记录错误但不中断响应
		}
	}
}

// captureRequestInfo 从入站 HTTP 请求中提取 URL、方法、头与体；读取后恢复 body 供后续处理器使用。
func captureRequestInfo(c *gin.Context) (*RequestInfo, error) {
	maskedQuery := util.MaskSensitiveQuery(c.Request.URL.RawQuery)
	url := c.Request.URL.Path
	if maskedQuery != "" {
		url += "?" + maskedQuery
	}

	method := c.Request.Method

	headers := make(map[string][]string)
	for key, values := range c.Request.Header {
		headers[key] = values
	}

	var body []byte
	if c.Request.Body != nil {
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			return nil, err
		}
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		body = bodyBytes
	}

	return &RequestInfo{
		URL:       url,
		Method:    method,
		Headers:   headers,
		Body:      body,
		RequestID: logging.GetGinRequestID(c),
		Timestamp: time.Now(),
	}, nil
}

// shouldLogRequest 判断是否记录该请求；跳过管理端点以防泄露密钥，其余路由（含模块提供）遵从 request-log 配置。
func shouldLogRequest(path string) bool {
	if strings.HasPrefix(path, "/v0/management") || strings.HasPrefix(path, "/management") {
		return false
	}

	if strings.HasPrefix(path, "/api") {
		return strings.HasPrefix(path, "/api/provider")
	}

	return true
}
