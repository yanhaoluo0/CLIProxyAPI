package auth

import (
	"strings"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/thinking"
)

type modelAliasEntry interface {
	GetName() string
	GetAlias() string
}

type oauthModelAliasTable struct {
	// reverse maps channel -> alias (lower) -> original upstream model name.
	reverse map[string]map[string]string
}

func compileOAuthModelAliasTable(aliases map[string][]internalconfig.OAuthModelAlias) *oauthModelAliasTable {
	if len(aliases) == 0 {
		return &oauthModelAliasTable{}
	}
	out := &oauthModelAliasTable{
		reverse: make(map[string]map[string]string, len(aliases)),
	}
	for rawChannel, entries := range aliases {
		channel := strings.ToLower(strings.TrimSpace(rawChannel))
		if channel == "" || len(entries) == 0 {
			continue
		}
		rev := make(map[string]string, len(entries))
		for _, entry := range entries {
			name := strings.TrimSpace(entry.Name)
			alias := strings.TrimSpace(entry.Alias)
			if name == "" || alias == "" {
				continue
			}
			if strings.EqualFold(name, alias) {
				continue
			}
			aliasKey := strings.ToLower(alias)
			if _, exists := rev[aliasKey]; exists {
				continue
			}
			rev[aliasKey] = name
		}
		if len(rev) > 0 {
			out.reverse[channel] = rev
		}
	}
	if len(out.reverse) == 0 {
		out.reverse = nil
	}
	return out
}

// SetOAuthModelAlias 更新执行期间使用的 OAuth 模型名别名表，别名按认证通道应用以解析上游模型名，同时保持客户端可见模型名不变以供翻译/响应格式化。
func (m *Manager) SetOAuthModelAlias(aliases map[string][]internalconfig.OAuthModelAlias) {
	if m == nil {
		return
	}
	table := compileOAuthModelAliasTable(aliases)
	// atomic.Value requires non-nil store values.
	if table == nil {
		table = &oauthModelAliasTable{}
	}
	m.oauthModelAlias.Store(table)
}

// applyOAuthModelAlias 从 OAuth 模型别名解析上游模型，若存在别名返回上游模型。
func (m *Manager) applyOAuthModelAlias(auth *Auth, requestedModel string) string {
	upstreamModel := m.resolveOAuthUpstreamModel(auth, requestedModel)
	if upstreamModel == "" {
		return requestedModel
	}
	return upstreamModel
}

func resolveModelAliasFromConfigModels(requestedModel string, models []modelAliasEntry) string {
	requestedModel = strings.TrimSpace(requestedModel)
	if requestedModel == "" {
		return ""
	}
	if len(models) == 0 {
		return ""
	}

	requestResult := thinking.ParseSuffix(requestedModel)
	base := requestResult.ModelName
	candidates := []string{base}
	if base != requestedModel {
		candidates = append(candidates, requestedModel)
	}

	preserveSuffix := func(resolved string) string {
		resolved = strings.TrimSpace(resolved)
		if resolved == "" {
			return ""
		}
		if thinking.ParseSuffix(resolved).HasSuffix {
			return resolved
		}
		if requestResult.HasSuffix && requestResult.RawSuffix != "" {
			return resolved + "(" + requestResult.RawSuffix + ")"
		}
		return resolved
	}

	for i := range models {
		name := strings.TrimSpace(models[i].GetName())
		alias := strings.TrimSpace(models[i].GetAlias())
		for _, candidate := range candidates {
			if candidate == "" {
				continue
			}
			if alias != "" && strings.EqualFold(alias, candidate) {
				if name != "" {
					return preserveSuffix(name)
				}
				return preserveSuffix(candidate)
			}
			if name != "" && strings.EqualFold(name, candidate) {
				return preserveSuffix(name)
			}
		}
	}
	return ""
}

// resolveOAuthUpstreamModel 从 OAuth 模型别名解析上游模型名，若存在别名返回请求别名对应的原始（上游）模型名。
//
// 若请求模型含 thinking 后缀（如 "gemini-2.5-pro(8192)"，后缀保留在返回模型名中；但若别名原始名已含后缀，配置后缀优先。
func (m *Manager) resolveOAuthUpstreamModel(auth *Auth, requestedModel string) string {
	return resolveUpstreamModelFromAliasTable(m, auth, requestedModel, modelAliasChannel(auth))
}

func resolveUpstreamModelFromAliasTable(m *Manager, auth *Auth, requestedModel, channel string) string {
	if m == nil || auth == nil {
		return ""
	}
	if channel == "" {
		return ""
	}

	// Extract thinking suffix from requested model using ParseSuffix
	requestResult := thinking.ParseSuffix(requestedModel)
	baseModel := requestResult.ModelName

	// Candidate keys to match: base model and raw input (handles suffix-parsing edge cases).
	candidates := []string{baseModel}
	if baseModel != requestedModel {
		candidates = append(candidates, requestedModel)
	}

	raw := m.oauthModelAlias.Load()
	table, _ := raw.(*oauthModelAliasTable)
	if table == nil || table.reverse == nil {
		return ""
	}
	rev := table.reverse[channel]
	if rev == nil {
		return ""
	}

	for _, candidate := range candidates {
		key := strings.ToLower(strings.TrimSpace(candidate))
		if key == "" {
			continue
		}
		original := strings.TrimSpace(rev[key])
		if original == "" {
			continue
		}
		if strings.EqualFold(original, baseModel) {
			return ""
		}

		// If config already has suffix, it takes priority.
		if thinking.ParseSuffix(original).HasSuffix {
			return original
		}
		// Preserve user's thinking suffix on the resolved model.
		if requestResult.HasSuffix && requestResult.RawSuffix != "" {
			return original + "(" + requestResult.RawSuffix + ")"
		}
		return original
	}

	return ""
}

// modelAliasChannel 从 Auth 对象提取 OAuth 模型别名通道，从 Auth 属性确定提供方与认证类型并委托 OAuthModelAliasChannel 进行实际通道解析。
func modelAliasChannel(auth *Auth) string {
	if auth == nil {
		return ""
	}
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	authKind := ""
	if auth.Attributes != nil {
		authKind = strings.ToLower(strings.TrimSpace(auth.Attributes["auth_kind"]))
	}
	if authKind == "" {
		if kind, _ := auth.AccountInfo(); strings.EqualFold(kind, "api_key") {
			authKind = "apikey"
		}
	}
	return OAuthModelAliasChannel(provider, authKind)
}

// OAuthModelAliasChannel 返回给定提供方与认证类型的 OAuth 模型别名通道名，若提供方/认证类型组合不支持 OAuth 模型别名（如 API key 认证）则返回空字符串。
func OAuthModelAliasChannel(provider, authKind string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	authKind = strings.ToLower(strings.TrimSpace(authKind))
	switch provider {
	case "gemini":
		// gemini provider uses gemini-api-key config, not oauth-model-alias.
		// OAuth-based gemini auth is converted to "gemini-cli" by the synthesizer.
		return ""
	case "vertex":
		if authKind == "apikey" {
			return ""
		}
		return "vertex"
	case "claude":
		if authKind == "apikey" {
			return ""
		}
		return "claude"
	case "codex":
		if authKind == "apikey" {
			return ""
		}
		return "codex"
	case "gemini-cli", "aistudio", "antigravity", "qwen", "iflow", "kimi":
		return provider
	default:
		return ""
	}
}
