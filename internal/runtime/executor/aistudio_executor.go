// Package executor 为多种 AI 服务提供运行时执行能力，本文件实现通过 WebSocket 传输将请求路由到 AI Studio 提供方的 AI Studio 执行器。
package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/wsrelay"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// AIStudioExecutor 通过 WebSocket 传输路由 AI Studio 请求。
type AIStudioExecutor struct {
	provider string
	relay    *wsrelay.Manager
	cfg      *config.Config
}

// NewAIStudioExecutor 创建新的 AI Studio 执行器实例。
func NewAIStudioExecutor(cfg *config.Config, provider string, relay *wsrelay.Manager) *AIStudioExecutor {
	return &AIStudioExecutor{provider: strings.ToLower(provider), relay: relay, cfg: cfg}
}

// Identifier 返回执行器标识。
func (e *AIStudioExecutor) Identifier() string { return "aistudio" }

// PrepareRequest 为执行准备 HTTP 请求（对 AI Studio 为 no-op）。
func (e *AIStudioExecutor) PrepareRequest(_ *http.Request, _ *cliproxyauth.Auth) error {
	return nil
}

// HttpRequest 通过 WebSocket relay 转发任意 HTTP 请求。
func (e *AIStudioExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("aistudio 执行器: 请求为 nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	if e.relay == nil {
		return nil, fmt.Errorf("aistudio 执行器: ws relay 为 nil")
	}
	if auth == nil || auth.ID == "" {
		return nil, fmt.Errorf("aistudio 执行器: 缺少 auth")
	}
	httpReq := req.WithContext(ctx)
	if httpReq.URL == nil || strings.TrimSpace(httpReq.URL.String()) == "" {
		return nil, fmt.Errorf("aistudio 执行器: 请求 URL 为空")
	}

	var body []byte
	if httpReq.Body != nil {
		b, errRead := io.ReadAll(httpReq.Body)
		if errRead != nil {
			return nil, errRead
		}
		body = b
		httpReq.Body = io.NopCloser(bytes.NewReader(b))
	}

	wsReq := &wsrelay.HTTPRequest{
		Method:  httpReq.Method,
		URL:     httpReq.URL.String(),
		Headers: httpReq.Header.Clone(),
		Body:    body,
	}
	wsResp, errRelay := e.relay.NonStream(ctx, auth.ID, wsReq)
	if errRelay != nil {
		return nil, errRelay
	}
	if wsResp == nil {
		return nil, fmt.Errorf("aistudio 执行器: ws 响应为 nil")
	}

	statusText := http.StatusText(wsResp.Status)
	if statusText == "" {
		statusText = "Unknown"
	}
	resp := &http.Response{
		StatusCode:    wsResp.Status,
		Status:        fmt.Sprintf("%d %s", wsResp.Status, statusText),
		Header:        wsResp.Headers.Clone(),
		Body:          io.NopCloser(bytes.NewReader(wsResp.Body)),
		ContentLength: int64(len(wsResp.Body)),
		Request:       httpReq,
	}
	return resp, nil
}

// Execute 对 AI Studio API 执行非流式请求。
func (e *AIStudioExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	if opts.Alt == "responses/compact" {
		return resp, statusErr{code: http.StatusNotImplemented, msg: "/responses/compact not supported"}
	}
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	reporter := newUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.trackFailure(ctx, &err)

	translatedReq, body, err := e.translateRequest(req, opts, false)
	if err != nil {
		return resp, err
	}

	endpoint := e.buildEndpoint(baseModel, body.action, opts.Alt)
	wsReq := &wsrelay.HTTPRequest{
		Method:  http.MethodPost,
		URL:     endpoint,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
		Body:    body.payload,
	}

	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	recordAPIRequest(ctx, e.cfg, upstreamRequestLog{
		URL:       endpoint,
		Method:    http.MethodPost,
		Headers:   wsReq.Headers.Clone(),
		Body:      body.payload,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})

	wsResp, err := e.relay.NonStream(ctx, authID, wsReq)
	if err != nil {
		recordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	recordAPIResponseMetadata(ctx, e.cfg, wsResp.Status, wsResp.Headers.Clone())
	if len(wsResp.Body) > 0 {
		appendAPIResponseChunk(ctx, e.cfg, wsResp.Body)
	}
	if wsResp.Status < 200 || wsResp.Status >= 300 {
		return resp, statusErr{code: wsResp.Status, msg: string(wsResp.Body)}
	}
	reporter.publish(ctx, parseGeminiUsage(wsResp.Body))
	var param any
	out := sdktranslator.TranslateNonStream(ctx, body.toFormat, opts.SourceFormat, req.Model, opts.OriginalRequest, translatedReq, wsResp.Body, &param)
	resp = cliproxyexecutor.Response{Payload: ensureColonSpacedJSON([]byte(out))}
	return resp, nil
}

// ExecuteStream 对 AI Studio API 执行流式请求。
func (e *AIStudioExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (stream <-chan cliproxyexecutor.StreamChunk, err error) {
	if opts.Alt == "responses/compact" {
		return nil, statusErr{code: http.StatusNotImplemented, msg: "/responses/compact not supported"}
	}
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	reporter := newUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.trackFailure(ctx, &err)

	translatedReq, body, err := e.translateRequest(req, opts, true)
	if err != nil {
		return nil, err
	}

	endpoint := e.buildEndpoint(baseModel, body.action, opts.Alt)
	wsReq := &wsrelay.HTTPRequest{
		Method:  http.MethodPost,
		URL:     endpoint,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
		Body:    body.payload,
	}
	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	recordAPIRequest(ctx, e.cfg, upstreamRequestLog{
		URL:       endpoint,
		Method:    http.MethodPost,
		Headers:   wsReq.Headers.Clone(),
		Body:      body.payload,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})
	wsStream, err := e.relay.Stream(ctx, authID, wsReq)
	if err != nil {
		recordAPIResponseError(ctx, e.cfg, err)
		return nil, err
	}
	firstEvent, ok := <-wsStream
	if !ok {
		err = fmt.Errorf("wsrelay: 流在开始前关闭")
		recordAPIResponseError(ctx, e.cfg, err)
		return nil, err
	}
	if firstEvent.Status > 0 && firstEvent.Status != http.StatusOK {
		metadataLogged := false
		if firstEvent.Status > 0 {
			recordAPIResponseMetadata(ctx, e.cfg, firstEvent.Status, firstEvent.Headers.Clone())
			metadataLogged = true
		}
		var body bytes.Buffer
		if len(firstEvent.Payload) > 0 {
			appendAPIResponseChunk(ctx, e.cfg, firstEvent.Payload)
			body.Write(firstEvent.Payload)
		}
		if firstEvent.Type == wsrelay.MessageTypeStreamEnd {
			return nil, statusErr{code: firstEvent.Status, msg: body.String()}
		}
		for event := range wsStream {
			if event.Err != nil {
				recordAPIResponseError(ctx, e.cfg, event.Err)
				if body.Len() == 0 {
					body.WriteString(event.Err.Error())
				}
				break
			}
			if !metadataLogged && event.Status > 0 {
				recordAPIResponseMetadata(ctx, e.cfg, event.Status, event.Headers.Clone())
				metadataLogged = true
			}
			if len(event.Payload) > 0 {
				appendAPIResponseChunk(ctx, e.cfg, event.Payload)
				body.Write(event.Payload)
			}
			if event.Type == wsrelay.MessageTypeStreamEnd {
				break
			}
		}
		return nil, statusErr{code: firstEvent.Status, msg: body.String()}
	}
	out := make(chan cliproxyexecutor.StreamChunk)
	stream = out
	go func(first wsrelay.StreamEvent) {
		defer close(out)
		var param any
		metadataLogged := false
		processEvent := func(event wsrelay.StreamEvent) bool {
			if event.Err != nil {
				recordAPIResponseError(ctx, e.cfg, event.Err)
				reporter.publishFailure(ctx)
				out <- cliproxyexecutor.StreamChunk{Err: fmt.Errorf("wsrelay: %v", event.Err)}
				return false
			}
			switch event.Type {
			case wsrelay.MessageTypeStreamStart:
				if !metadataLogged && event.Status > 0 {
					recordAPIResponseMetadata(ctx, e.cfg, event.Status, event.Headers.Clone())
					metadataLogged = true
				}
			case wsrelay.MessageTypeStreamChunk:
				if len(event.Payload) > 0 {
					appendAPIResponseChunk(ctx, e.cfg, event.Payload)
					filtered := FilterSSEUsageMetadata(event.Payload)
					if detail, ok := parseGeminiStreamUsage(filtered); ok {
						reporter.publish(ctx, detail)
					}
					lines := sdktranslator.TranslateStream(ctx, body.toFormat, opts.SourceFormat, req.Model, opts.OriginalRequest, translatedReq, filtered, &param)
					for i := range lines {
						out <- cliproxyexecutor.StreamChunk{Payload: ensureColonSpacedJSON([]byte(lines[i]))}
					}
					break
				}
			case wsrelay.MessageTypeStreamEnd:
				return false
			case wsrelay.MessageTypeHTTPResp:
				if !metadataLogged && event.Status > 0 {
					recordAPIResponseMetadata(ctx, e.cfg, event.Status, event.Headers.Clone())
					metadataLogged = true
				}
				if len(event.Payload) > 0 {
					appendAPIResponseChunk(ctx, e.cfg, event.Payload)
				}
				lines := sdktranslator.TranslateStream(ctx, body.toFormat, opts.SourceFormat, req.Model, opts.OriginalRequest, translatedReq, event.Payload, &param)
				for i := range lines {
					out <- cliproxyexecutor.StreamChunk{Payload: ensureColonSpacedJSON([]byte(lines[i]))}
				}
				reporter.publish(ctx, parseGeminiUsage(event.Payload))
				return false
			case wsrelay.MessageTypeError:
				recordAPIResponseError(ctx, e.cfg, event.Err)
				reporter.publishFailure(ctx)
				out <- cliproxyexecutor.StreamChunk{Err: fmt.Errorf("wsrelay: %v", event.Err)}
				return false
			}
			return true
		}
		if !processEvent(first) {
			return
		}
		for event := range wsStream {
			if !processEvent(event) {
				return
			}
		}
	}(firstEvent)
	return stream, nil
}

// CountTokens 使用 AI Studio API 为给定请求计 token 数。
func (e *AIStudioExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	_, body, err := e.translateRequest(req, opts, false)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}

	body.payload, _ = sjson.DeleteBytes(body.payload, "generationConfig")
	body.payload, _ = sjson.DeleteBytes(body.payload, "tools")
	body.payload, _ = sjson.DeleteBytes(body.payload, "safetySettings")

	endpoint := e.buildEndpoint(baseModel, "countTokens", "")
	wsReq := &wsrelay.HTTPRequest{
		Method:  http.MethodPost,
		URL:     endpoint,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
		Body:    body.payload,
	}
	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	recordAPIRequest(ctx, e.cfg, upstreamRequestLog{
		URL:       endpoint,
		Method:    http.MethodPost,
		Headers:   wsReq.Headers.Clone(),
		Body:      body.payload,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})
	resp, err := e.relay.NonStream(ctx, authID, wsReq)
	if err != nil {
		recordAPIResponseError(ctx, e.cfg, err)
		return cliproxyexecutor.Response{}, err
	}
	recordAPIResponseMetadata(ctx, e.cfg, resp.Status, resp.Headers.Clone())
	if len(resp.Body) > 0 {
		appendAPIResponseChunk(ctx, e.cfg, resp.Body)
	}
	if resp.Status < 200 || resp.Status >= 300 {
		return cliproxyexecutor.Response{}, statusErr{code: resp.Status, msg: string(resp.Body)}
	}
	totalTokens := gjson.GetBytes(resp.Body, "totalTokens").Int()
	if totalTokens <= 0 {
		return cliproxyexecutor.Response{}, fmt.Errorf("wsrelay: 响应中缺少 totalTokens")
	}
	translated := sdktranslator.TranslateTokenCount(ctx, body.toFormat, opts.SourceFormat, totalTokens, resp.Body)
	return cliproxyexecutor.Response{Payload: []byte(translated)}, nil
}

// Refresh 刷新认证凭证（对 AI Studio 为 no-op）。
func (e *AIStudioExecutor) Refresh(_ context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	return auth, nil
}

type translatedPayload struct {
	payload  []byte
	action   string
	toFormat sdktranslator.Format
}

func (e *AIStudioExecutor) translateRequest(req cliproxyexecutor.Request, opts cliproxyexecutor.Options, stream bool) ([]byte, translatedPayload, error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName

	from := opts.SourceFormat
	to := sdktranslator.FromString("gemini")
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := originalPayloadSource
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, originalPayload, stream)
	payload := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, stream)
	payload, err := thinking.ApplyThinking(payload, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return nil, translatedPayload{}, err
	}
	payload = fixGeminiImageAspectRatio(baseModel, payload)
	requestedModel := payloadRequestedModel(opts, req.Model)
	payload = applyPayloadConfigWithRoot(e.cfg, baseModel, to.String(), "", payload, originalTranslated, requestedModel)
	payload, _ = sjson.DeleteBytes(payload, "generationConfig.maxOutputTokens")
	payload, _ = sjson.DeleteBytes(payload, "generationConfig.responseMimeType")
	payload, _ = sjson.DeleteBytes(payload, "generationConfig.responseJsonSchema")
	metadataAction := "generateContent"
	if req.Metadata != nil {
		if action, _ := req.Metadata["action"].(string); action == "countTokens" {
			metadataAction = action
		}
	}
	action := metadataAction
	if stream && action != "countTokens" {
		action = "streamGenerateContent"
	}
	payload, _ = sjson.DeleteBytes(payload, "session_id")
	return payload, translatedPayload{payload: payload, action: action, toFormat: to}, nil
}

func (e *AIStudioExecutor) buildEndpoint(model, action, alt string) string {
	base := fmt.Sprintf("%s/%s/models/%s:%s", glEndpoint, glAPIVersion, model, action)
	if action == "streamGenerateContent" {
		if alt == "" {
			return base + "?alt=sse"
		}
		return base + "?$alt=" + url.QueryEscape(alt)
	}
	if alt != "" && action != "countTokens" {
		return base + "?$alt=" + url.QueryEscape(alt)
	}
	return base
}

// ensureColonSpacedJSON 规范化 JSON 对象，使冒号后跟单个空格，同时保持其他紧凑；非 JSON 输入原样返回。
func ensureColonSpacedJSON(payload []byte) []byte {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return payload
	}

	var decoded any
	if err := json.Unmarshal(trimmed, &decoded); err != nil {
		return payload
	}

	indented, err := json.MarshalIndent(decoded, "", "  ")
	if err != nil {
		return payload
	}

	compacted := make([]byte, 0, len(indented))
	inString := false
	skipSpace := false

	for i := 0; i < len(indented); i++ {
		ch := indented[i]
		if ch == '"' {
			// A quote is escaped only when preceded by an odd number of consecutive backslashes.
			// For example: "\\\"" keeps the quote inside the string, but "\\\\" closes the string.
			backslashes := 0
			for j := i - 1; j >= 0 && indented[j] == '\\'; j-- {
				backslashes++
			}
			if backslashes%2 == 0 {
				inString = !inString
			}
		}

		if !inString {
			if ch == '\n' || ch == '\r' {
				skipSpace = true
				continue
			}
			if skipSpace {
				if ch == ' ' || ch == '\t' {
					continue
				}
				skipSpace = false
			}
		}

		compacted = append(compacted, ch)
	}

	return compacted
}
