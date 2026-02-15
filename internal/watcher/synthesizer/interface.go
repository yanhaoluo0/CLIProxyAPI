// Package synthesizer provides auth synthesis strategies for the watcher package.
// It implements the Strategy pattern to support multiple auth sources:
// - ConfigSynthesizer: generates Auth entries from config API keys
// - FileSynthesizer: generates Auth entries from OAuth JSON files
package synthesizer

import (
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// AuthSynthesizer 定义从各种来源生成 Auth 认证条目的接口。
type AuthSynthesizer interface {
	// Synthesize generates Auth entries from the given context.
	// Returns a slice of Auth pointers and any error encountered.
	Synthesize(ctx *SynthesisContext) ([]*coreauth.Auth, error)
}
