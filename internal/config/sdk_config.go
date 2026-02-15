// Package config 提供 CLI Proxy API 服务端配置管理（见 config.go）。
package config

// SDKConfig 表示从 YAML 加载的应用配置中的 SDK 相关部分。
type SDKConfig struct {
	ProxyURL                   string          `yaml:"proxy-url" json:"proxy-url"`
	ForceModelPrefix           bool            `yaml:"force-model-prefix" json:"force-model-prefix"`
	RequestLog                 bool            `yaml:"request-log" json:"request-log"`
	APIKeys                    []string        `yaml:"api-keys" json:"api-keys"`
	Streaming                  StreamingConfig `yaml:"streaming" json:"streaming"`
	NonStreamKeepAliveInterval int             `yaml:"nonstream-keepalive-interval,omitempty" json:"nonstream-keepalive-interval,omitempty"`
}

// StreamingConfig 为服务端流式行为配置（心跳与安全引导重试）。
type StreamingConfig struct {
	KeepAliveSeconds int `yaml:"keepalive-seconds,omitempty" json:"keepalive-seconds,omitempty"`
	BootstrapRetries int `yaml:"bootstrap-retries,omitempty" json:"bootstrap-retries,omitempty"`
}
