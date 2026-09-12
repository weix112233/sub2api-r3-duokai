package tlsfingerprint

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

const MaxProfileYAMLBytes = 64 * 1024

// ProfileDocument accepts either a profile or a single named collector export.
// Parsing is shared by administration and external capture fixtures.
type ProfileDocument struct {
	Profile     `yaml:",inline"`
	Description *string `json:"description" yaml:"description"`
}

func ParseProfileYAML(data []byte) (*ProfileDocument, error) {
	if len(data) == 0 || len(data) > MaxProfileYAMLBytes {
		return nil, fmt.Errorf("profile YAML must contain 1..%d bytes", MaxProfileYAMLBytes)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("invalid profile YAML: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("exactly one YAML document is required")
	}
	if len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("profile must be a YAML mapping")
	}
	node := root.Content[0]
	if len(node.Content) == 2 && node.Content[1].Kind == yaml.MappingNode {
		node = node.Content[1]
	}
	// Re-encode the selected mapping to retain strict field/duplicate validation.
	selected, err := yaml.Marshal(node)
	if err != nil {
		return nil, err
	}
	strict := yaml.NewDecoder(bytes.NewReader(selected))
	strict.KnownFields(true)
	var doc ProfileDocument
	if err := strict.Decode(&doc); err != nil {
		return nil, fmt.Errorf("invalid profile: %w", err)
	}
	doc.Name = strings.TrimSpace(doc.Name)
	if doc.Name == "" {
		return nil, fmt.Errorf("profile name is required")
	}
	if err := doc.Validate(); err != nil {
		return nil, err
	}
	return &doc, nil
}
