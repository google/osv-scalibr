// Package metadata provides the metadata structure for MCP configuration files.
package metadata

import (
	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// Metadata represents the metadata extracted from an MCP configuration file.
type Metadata struct {
	Command   string            `json:"command"`
	Args      []string          `json:"args"`
	Env       map[string]string `json:"env"`
	RuntimeID string            `json:"runtime_id"`
}

// ToStruct converts the proto structure to the internal metadata structure.
func ToStruct(p *spb.MCPMetadata) *Metadata {
	if p == nil {
		return nil
	}
	return &Metadata{
		Command:   p.Command,
		Args:      p.Args,
		Env:       p.Env,
		RuntimeID: p.RuntimeId,
	}
}

// SetProto sets the MCPMetadata field in the Package proto.
func (m *Metadata) SetProto(p *spb.Package) {
	if m == nil || p == nil {
		return
	}
	p.Metadata = &spb.Package_McpMetadata{
		McpMetadata: &spb.MCPMetadata{
			Command: m.Command,
			Args:    m.Args,
			Env:     m.Env,
		},
	}
}
