// Package logging 提供 Gin 的 HTTP 请求日志与 panic 恢复中间件。
// 将 Gin 与 logrus 结合，对请求/响应与错误进行结构化记录，并支持 panic 恢复。
package logging

import (
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	log "github.com/sirupsen/logrus"
)

// aiAPIPrefixes 定义需要分配请求 ID 的 AI API 路径前缀。
var aiAPIPrefixes = []string{
	"/v1/chat/completions",
	"/v1/completions",
	"/v1/messages",
	"/v1/responses",
	"/v1beta/models/",
	"/api/provider/",
}

const skipGinLogKey = "__gin_skip_request_logging__"

// GinLogrusLogger 返回使用 logrus 记录 HTTP 请求与响应的 Gin 中间件。
// 记录方法、路径、状态码、耗时、客户端 IP 及错误信息；仅对 AI API 请求注入请求 ID。
//
// 输出格式（AI API）: [日期时间] [请求ID] [级别] 状态码 | 耗时 | 客户端IP | 方法 "路径"
// 输出格式（其他）:   [日期时间] [--------] [级别] 状态码 | 耗时 | 客户端IP | 方法 "路径"
func GinLogrusLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := util.MaskSensitiveQuery(c.Request.URL.RawQuery)

		// 仅对 AI API 路径生成请求 ID
		var requestID string
		if isAIAPIPath(path) {
			requestID = GenerateRequestID()
			SetGinRequestID(c, requestID)
			ctx := WithRequestID(c.Request.Context(), requestID)
			c.Request = c.Request.WithContext(ctx)
		}

		c.Next()

		if shouldSkipGinRequestLogging(c) {
			return
		}

		if raw != "" {
			path = path + "?" + raw
		}

		latency := time.Since(start)
		if latency > time.Minute {
			latency = latency.Truncate(time.Second)
		} else {
			latency = latency.Truncate(time.Millisecond)
		}

		statusCode := c.Writer.Status()
		clientIP := c.ClientIP()
		method := c.Request.Method
		errorMessage := c.Errors.ByType(gin.ErrorTypePrivate).String()

		if requestID == "" {
			requestID = "--------"
		}
		logLine := fmt.Sprintf("%3d | %13v | %15s | %-7s \"%s\"", statusCode, latency, clientIP, method, path)
		if errorMessage != "" {
			logLine = logLine + " | " + errorMessage
		}

		entry := log.WithField("request_id", requestID)

		switch {
		case statusCode >= http.StatusInternalServerError:
			entry.Error(logLine)
		case statusCode >= http.StatusBadRequest:
			entry.Warn(logLine)
		default:
			entry.Info(logLine)
		}
	}
}

// isAIAPIPath 判断路径是否为需要请求 ID 的 AI API 端点。
func isAIAPIPath(path string) bool {
	for _, prefix := range aiAPIPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// GinLogrusRecovery 返回从 panic 中恢复并交由 logrus 记录的 Gin 中间件。
// 发生 panic 时记录 panic 值、堆栈与请求路径，并向客户端返回 500。
func GinLogrusRecovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		if err, ok := recovered.(error); ok && errors.Is(err, http.ErrAbortHandler) {
			panic(http.ErrAbortHandler)
		}

		log.WithFields(log.Fields{
			"panic": recovered,
			"stack": string(debug.Stack()),
			"path":  c.Request.URL.Path,
		}).Error("从 panic 中恢复")

		c.AbortWithStatus(http.StatusInternalServerError)
	})
}

// SkipGinRequestLogging 标记当前 Gin 上下文，使 GinLogrusLogger 不再为该请求输出日志行。
func SkipGinRequestLogging(c *gin.Context) {
	if c == nil {
		return
	}
	c.Set(skipGinLogKey, true)
}

func shouldSkipGinRequestLogging(c *gin.Context) bool {
	if c == nil {
		return false
	}
	val, exists := c.Get(skipGinLogKey)
	if !exists {
		return false
	}
	flag, ok := val.(bool)
	return ok && flag
}
