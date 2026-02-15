// Package cliproxy 提供 CLI Proxy API 的核心服务实现，包含生命周期管理、认证处理、文件监听，
// 以及通过统一接口与各种 AI 服务提供方的集成。
package cliproxy

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/watcher"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

// TokenClientProvider 加载由存储认证令牌支持的客户端，提供从多种来源加载认证令牌并为 AI 服务提供方创建客户端的接口。
type TokenClientProvider interface {
	// Load loads token-based clients from the configured source.
	//
	// Parameters:
	//   - ctx: The context for the loading operation
	//   - cfg: The application configuration
	//
	// Returns:
	//   - *TokenClientResult: The result containing loaded clients
	//   - error: An error if loading fails
	Load(ctx context.Context, cfg *config.Config) (*TokenClientResult, error)
}

// TokenClientResult 表示从持久化令牌生成的客户端，包含加载操作的元数据与成功认证数。
type TokenClientResult struct {
	// SuccessfulAuthed is the number of successfully authenticated clients.
	SuccessfulAuthed int
}

// APIKeyClientProvider 加载由配置 API key 直接支持的客户端，提供为各种 AI 服务提供方加载 API key 客户端的接口。
type APIKeyClientProvider interface {
	// Load loads API key-based clients from the configuration.
	//
	// Parameters:
	//   - ctx: The context for the loading operation
	//   - cfg: The application configuration
	//
	// Returns:
	//   - *APIKeyClientResult: The result containing loaded clients
	//   - error: An error if loading fails
	Load(ctx context.Context, cfg *config.Config) (*APIKeyClientResult, error)
}

// APIKeyClientResult 由 APIKeyClientProvider.Load() 返回。
type APIKeyClientResult struct {
	// GeminiKeyCount is the number of Gemini API keys loaded
	GeminiKeyCount int

	// VertexCompatKeyCount is the number of Vertex-compatible API keys loaded
	VertexCompatKeyCount int

	// ClaudeKeyCount is the number of Claude API keys loaded
	ClaudeKeyCount int

	// CodexKeyCount is the number of Codex API keys loaded
	CodexKeyCount int

	// OpenAICompatCount is the number of OpenAI compatibility API keys loaded
	OpenAICompatCount int
}

// WatcherFactory 为配置与令牌变更创建监听器，reload 回调在检测到变更时接收更新后的配置。
type WatcherFactory func(configPath, authDir string, reload func(*config.Config)) (*WatcherWrapper, error)

// WatcherWrapper 暴露 SDK 所需的监听器方法子集。
type WatcherWrapper struct {
	start func(ctx context.Context) error
	stop  func() error

	setConfig             func(cfg *config.Config)
	snapshotAuths         func() []*coreauth.Auth
	setUpdateQueue        func(queue chan<- watcher.AuthUpdate)
	dispatchRuntimeUpdate func(update watcher.AuthUpdate) bool
}

// Start 代理底层监听器 Start 实现。
func (w *WatcherWrapper) Start(ctx context.Context) error {
	if w == nil || w.start == nil {
		return nil
	}
	return w.start(ctx)
}

// Stop 代理底层监听器 Stop 实现。
func (w *WatcherWrapper) Stop() error {
	if w == nil || w.stop == nil {
		return nil
	}
	return w.stop()
}

// SetConfig 更新监听器配置缓存。
func (w *WatcherWrapper) SetConfig(cfg *config.Config) {
	if w == nil || w.setConfig == nil {
		return
	}
	w.setConfig(cfg)
}

// DispatchRuntimeAuthUpdate 在可用时将运行时认证更新（如 WebSocket 提供方）转发到监听器管理的认证更新队列。
func (w *WatcherWrapper) DispatchRuntimeAuthUpdate(update watcher.AuthUpdate) bool {
	if w == nil || w.dispatchRuntimeUpdate == nil {
		return false
	}
	return w.dispatchRuntimeUpdate(update)
}

// SetClients 更新监听器文件支持的客户端注册表。

// SnapshotClients 返回底层监听器的当前组合客户端快照。

// SnapshotAuths 返回从旧版客户端派生当前认证条目。
func (w *WatcherWrapper) SnapshotAuths() []*coreauth.Auth {
	if w == nil || w.snapshotAuths == nil {
		return nil
	}
	return w.snapshotAuths()
}

// SetAuthUpdateQueue 注册用于传播认证更新的通道。
func (w *WatcherWrapper) SetAuthUpdateQueue(queue chan<- watcher.AuthUpdate) {
	if w == nil || w.setUpdateQueue == nil {
		return
	}
	w.setUpdateQueue(queue)
}
