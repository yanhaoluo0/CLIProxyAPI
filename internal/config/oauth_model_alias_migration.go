package config

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// antigravityModelConversionTable 在迁移时将 antigravity 渠道的旧内置别名映射为实际模型名。
var antigravityModelConversionTable = map[string]string{
	"gemini-2.5-computer-use-preview-10-2025": "rev19-uic3-1p",
	"gemini-3-pro-image-preview":              "gemini-3-pro-image",
	"gemini-3-pro-preview":                    "gemini-3-pro-high",
	"gemini-3-flash-preview":                  "gemini-3-flash",
	"gemini-claude-sonnet-4-5":                "claude-sonnet-4-5",
	"gemini-claude-sonnet-4-5-thinking":       "claude-sonnet-4-5-thinking",
	"gemini-claude-opus-4-5-thinking":         "claude-opus-4-5-thinking",
	"gemini-claude-opus-4-6-thinking":         "claude-opus-4-6-thinking",
}

// defaultAntigravityAliases 在配置中不存在 oauth-model-alias 与 oauth-model-mappings 时，返回 antigravity 渠道的默认 oauth-model-alias。
func defaultAntigravityAliases() []OAuthModelAlias {
	return []OAuthModelAlias{
		{Name: "rev19-uic3-1p", Alias: "gemini-2.5-computer-use-preview-10-2025"},
		{Name: "gemini-3-pro-image", Alias: "gemini-3-pro-image-preview"},
		{Name: "gemini-3-pro-high", Alias: "gemini-3-pro-preview"},
		{Name: "gemini-3-flash", Alias: "gemini-3-flash-preview"},
		{Name: "claude-sonnet-4-5", Alias: "gemini-claude-sonnet-4-5"},
		{Name: "claude-sonnet-4-5-thinking", Alias: "gemini-claude-sonnet-4-5-thinking"},
		{Name: "claude-opus-4-5-thinking", Alias: "gemini-claude-opus-4-5-thinking"},
		{Name: "claude-opus-4-6-thinking", Alias: "gemini-claude-opus-4-6-thinking"},
	}
}

// MigrateOAuthModelAlias 在启动时检查并执行从 oauth-model-mappings 到 oauth-model-alias 的迁移，若执行了迁移则返回 true。
// 流程：若已存在 oauth-model-alias 则跳过；若存在 oauth-model-mappings 则转换并迁移（antigravity 会转换旧内置别名）；若两者都不存在则写入默认 antigravity 配置。
func MigrateOAuthModelAlias(configFile string) (bool, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if len(data) == 0 {
		return false, nil
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return false, nil
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return false, nil
	}
	rootMap := root.Content[0]
	if rootMap == nil || rootMap.Kind != yaml.MappingNode {
		return false, nil
	}

	if findMapKeyIndex(rootMap, "oauth-model-alias") >= 0 {
		return false, nil
	}

	oldIdx := findMapKeyIndex(rootMap, "oauth-model-mappings")
	if oldIdx >= 0 {
		return migrateFromOldField(configFile, &root, rootMap, oldIdx)
	}
	return addDefaultAntigravityConfig(configFile, &root, rootMap)
}

// migrateFromOldField 将 oauth-model-mappings 转为 oauth-model-alias 并写回。
func migrateFromOldField(configFile string, root *yaml.Node, rootMap *yaml.Node, oldIdx int) (bool, error) {
	if oldIdx+1 >= len(rootMap.Content) {
		return false, nil
	}
	oldValue := rootMap.Content[oldIdx+1]
	if oldValue == nil || oldValue.Kind != yaml.MappingNode {
		return false, nil
	}

	oldAliases := parseOldAliasNode(oldValue)
	if len(oldAliases) == 0 {
		removeMapKeyByIndex(rootMap, oldIdx)
		return writeYAMLNode(configFile, root)
	}

	// Convert model names for antigravity channel
	newAliases := make(map[string][]OAuthModelAlias, len(oldAliases))
	for channel, entries := range oldAliases {
		converted := make([]OAuthModelAlias, 0, len(entries))
		for _, entry := range entries {
			newEntry := OAuthModelAlias{
				Name:  entry.Name,
				Alias: entry.Alias,
				Fork:  entry.Fork,
			}
			if strings.EqualFold(channel, "antigravity") {
				if actual, ok := antigravityModelConversionTable[entry.Name]; ok {
					newEntry.Name = actual
				}
			}
			converted = append(converted, newEntry)
		}
		newAliases[channel] = converted
	}

	// For antigravity channel, supplement missing default aliases
	if antigravityEntries, exists := newAliases["antigravity"]; exists {
		// Build a set of already configured model names (upstream names)
		configuredModels := make(map[string]bool, len(antigravityEntries))
		for _, entry := range antigravityEntries {
			configuredModels[entry.Name] = true
		}

		// Add missing default aliases
		for _, defaultAlias := range defaultAntigravityAliases() {
			if !configuredModels[defaultAlias.Name] {
				antigravityEntries = append(antigravityEntries, defaultAlias)
			}
		}
		newAliases["antigravity"] = antigravityEntries
	}

	// Build new node
	newNode := buildOAuthModelAliasNode(newAliases)

	// Replace old key with new key and value
	rootMap.Content[oldIdx].Value = "oauth-model-alias"
	rootMap.Content[oldIdx+1] = newNode

	return writeYAMLNode(configFile, root)
}

// addDefaultAntigravityConfig adds the default antigravity configuration
func addDefaultAntigravityConfig(configFile string, root *yaml.Node, rootMap *yaml.Node) (bool, error) {
	defaults := map[string][]OAuthModelAlias{
		"antigravity": defaultAntigravityAliases(),
	}
	newNode := buildOAuthModelAliasNode(defaults)

	// Add new key-value pair
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "oauth-model-alias"}
	rootMap.Content = append(rootMap.Content, keyNode, newNode)

	return writeYAMLNode(configFile, root)
}

// parseOldAliasNode parses the old oauth-model-mappings node structure
func parseOldAliasNode(node *yaml.Node) map[string][]OAuthModelAlias {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	result := make(map[string][]OAuthModelAlias)
	for i := 0; i+1 < len(node.Content); i += 2 {
		channelNode := node.Content[i]
		entriesNode := node.Content[i+1]
		if channelNode == nil || entriesNode == nil {
			continue
		}
		channel := strings.ToLower(strings.TrimSpace(channelNode.Value))
		if channel == "" || entriesNode.Kind != yaml.SequenceNode {
			continue
		}
		entries := make([]OAuthModelAlias, 0, len(entriesNode.Content))
		for _, entryNode := range entriesNode.Content {
			if entryNode == nil || entryNode.Kind != yaml.MappingNode {
				continue
			}
			entry := parseAliasEntry(entryNode)
			if entry.Name != "" && entry.Alias != "" {
				entries = append(entries, entry)
			}
		}
		if len(entries) > 0 {
			result[channel] = entries
		}
	}
	return result
}

// parseAliasEntry parses a single alias entry node
func parseAliasEntry(node *yaml.Node) OAuthModelAlias {
	var entry OAuthModelAlias
	for i := 0; i+1 < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valNode := node.Content[i+1]
		if keyNode == nil || valNode == nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(keyNode.Value)) {
		case "name":
			entry.Name = strings.TrimSpace(valNode.Value)
		case "alias":
			entry.Alias = strings.TrimSpace(valNode.Value)
		case "fork":
			entry.Fork = strings.ToLower(strings.TrimSpace(valNode.Value)) == "true"
		}
	}
	return entry
}

// buildOAuthModelAliasNode creates a YAML node for oauth-model-alias
func buildOAuthModelAliasNode(aliases map[string][]OAuthModelAlias) *yaml.Node {
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for channel, entries := range aliases {
		channelNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: channel}
		entriesNode := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, entry := range entries {
			entryNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			entryNode.Content = append(entryNode.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "name"},
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: entry.Name},
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "alias"},
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: entry.Alias},
			)
			if entry.Fork {
				entryNode.Content = append(entryNode.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "fork"},
					&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"},
				)
			}
			entriesNode.Content = append(entriesNode.Content, entryNode)
		}
		node.Content = append(node.Content, channelNode, entriesNode)
	}
	return node
}

// removeMapKeyByIndex removes a key-value pair from a mapping node by index
func removeMapKeyByIndex(mapNode *yaml.Node, keyIdx int) {
	if mapNode == nil || mapNode.Kind != yaml.MappingNode {
		return
	}
	if keyIdx < 0 || keyIdx+1 >= len(mapNode.Content) {
		return
	}
	mapNode.Content = append(mapNode.Content[:keyIdx], mapNode.Content[keyIdx+2:]...)
}

// writeYAMLNode writes the YAML node tree back to file
func writeYAMLNode(configFile string, root *yaml.Node) (bool, error) {
	f, err := os.Create(configFile)
	if err != nil {
		return false, err
	}
	defer f.Close()

	enc := yaml.NewEncoder(f)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return false, err
	}
	if err := enc.Close(); err != nil {
		return false, err
	}
	return true, nil
}
