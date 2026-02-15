package config

import "strings"

// VertexCompatKey 为 Vertex AI 兼容 API 密钥配置，支持使用 Vertex 风格路径但用 API Key 认证的第三方服务（如 zenmux.ai）。
type VertexCompatKey struct {
	APIKey   string              `yaml:"api-key" json:"api-key"`
	Priority int                 `yaml:"priority,omitempty" json:"priority,omitempty"`
	Prefix   string              `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	BaseURL  string              `yaml:"base-url,omitempty" json:"base-url,omitempty"`
	ProxyURL string              `yaml:"proxy-url,omitempty" json:"proxy-url,omitempty"`
	Headers  map[string]string   `yaml:"headers,omitempty" json:"headers,omitempty"`
	Models   []VertexCompatModel `yaml:"models,omitempty" json:"models,omitempty"`
}

func (k VertexCompatKey) GetAPIKey() string  { return k.APIKey }
func (k VertexCompatKey) GetBaseURL() string { return k.BaseURL }

// VertexCompatModel 为 Vertex 兼容下的模型配置，含上游模型名与客户端别名。
type VertexCompatModel struct {
	Name  string `yaml:"name" json:"name"`
	Alias string `yaml:"alias" json:"alias"`
}

func (m VertexCompatModel) GetName() string  { return m.Name }
func (m VertexCompatModel) GetAlias() string { return m.Alias }

// SanitizeVertexCompatKeys 对 Vertex 兼容 API 密钥去重并规范化。
func (cfg *Config) SanitizeVertexCompatKeys() {
	if cfg == nil {
		return
	}

	seen := make(map[string]struct{}, len(cfg.VertexCompatAPIKey))
	out := cfg.VertexCompatAPIKey[:0]
	for i := range cfg.VertexCompatAPIKey {
		entry := cfg.VertexCompatAPIKey[i]
		entry.APIKey = strings.TrimSpace(entry.APIKey)
		if entry.APIKey == "" {
			continue
		}
		entry.Prefix = normalizeModelPrefix(entry.Prefix)
		entry.BaseURL = strings.TrimSpace(entry.BaseURL)
		if entry.BaseURL == "" {
			continue
		}
		entry.ProxyURL = strings.TrimSpace(entry.ProxyURL)
		entry.Headers = NormalizeHeaders(entry.Headers)

		sanitizedModels := make([]VertexCompatModel, 0, len(entry.Models))
		for _, model := range entry.Models {
			model.Alias = strings.TrimSpace(model.Alias)
			model.Name = strings.TrimSpace(model.Name)
			if model.Alias != "" && model.Name != "" {
				sanitizedModels = append(sanitizedModels, model)
			}
		}
		entry.Models = sanitizedModels

		uniqueKey := entry.APIKey + "|" + entry.BaseURL
		if _, exists := seen[uniqueKey]; exists {
			continue
		}
		seen[uniqueKey] = struct{}{}
		out = append(out, entry)
	}
	cfg.VertexCompatAPIKey = out
}
