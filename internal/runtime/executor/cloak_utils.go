package executor

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// userIDPattern 匹配 Claude Code 格式: user_[64-hex]_account__session_[uuid-v4]
var userIDPattern = regexp.MustCompile(`^user_[a-fA-F0-9]{64}_account__session_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// generateFakeUserID 生成符合 Claude Code 格式的伪造 user ID，格式: user_[64-hex-chars]_account__session_[UUID-v4]
func generateFakeUserID() string {
	hexBytes := make([]byte, 32)
	_, _ = rand.Read(hexBytes)
	hexPart := hex.EncodeToString(hexBytes)
	uuidPart := uuid.New().String()
	return "user_" + hexPart + "_account__session_" + uuidPart
}

// isValidUserID 检查 user ID 是否符合 Claude Code 格式。
func isValidUserID(userID string) bool {
	return userIDPattern.MatchString(userID)
}

// shouldCloak 根据配置与客户端 User-Agent 判断是否应做cloak；返回 true 表示应应用 cloak。
func shouldCloak(cloakMode string, userAgent string) bool {
	switch strings.ToLower(cloakMode) {
	case "always":
		return true
	case "never":
		return false
	default: // "auto" or empty
		// If client is Claude Code, don't cloak
		return !strings.HasPrefix(userAgent, "claude-cli")
	}
}

// isClaudeCodeClient 检查 User-Agent 是否表示 Claude Code 客户端。
func isClaudeCodeClient(userAgent string) bool {
	return strings.HasPrefix(userAgent, "claude-cli")
}
