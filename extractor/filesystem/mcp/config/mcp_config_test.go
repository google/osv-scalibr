package config_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/mcp/config"
	"github.com/google/osv-scalibr/extractor/filesystem/mcp/config/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "mcp_json",
			path: "path/to/mcp.json",
			want: true,
		},
		{
			name: "dot_mcp_json",
			path: "path/to/.mcp.json",
			want: true,
		},
		{
			name: "mcp_servers_json",
			path: "path/to/mcp-servers.json",
			want: true,
		},
		{
			name: "vscode_mcp_json",
			path: "path/to/.vscode/mcp.json",
			want: true,
		},
		{
			name: "other_json",
			path: "path/to/other.json",
			want: false,
		},
		{
			name: "should_skip_node_modules",
			path: "path/to/node_modules/mcp.json",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := config.New(nil)
			if err != nil {
				t.Fatalf("config.New() error = %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.path, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%q) = %v; want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		Name          string
		Path          string
		Content       string
		WantInventory inventory.Inventory
	}{
		{
			Name: "Valid_mcp_json_with_npx_and_uvx",
			Path: "test/mcp.json",
			Content: `{
				"mcpServers": {
					"filesystem": {
						"command": "npx",
						"args": [
							"-y",
							"@modelcontextprotocol/server-filesystem",
							"/path/to/allowed/files"
						],
						"env": {
							"API_KEY": "secret"
						}
					},
					"python-server": {
						"command": "uvx",
						"args": [
							"mcp-server-git",
							"--repository",
							"."
						]
					}
				}
			}`,
			WantInventory: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:      "@modelcontextprotocol/server-filesystem",
						Version:   "",
						PURLType:  purl.TypeNPM,
						Locations: []string{"test/mcp.json"},
						Metadata: &metadata.Metadata{
							Command:   "npx",
							Args:      []string{"-y", "@modelcontextprotocol/server-filesystem", "/path/to/allowed/files"},
							Env:       map[string]string{"API_KEY": "[REDACTED]"},
							RuntimeID: "filesystem",
						},
					},
					{
						Name:      "mcp-server-git",
						PURLType:  purl.TypePyPi,
						Locations: []string{"test/mcp.json"},
						Metadata: &metadata.Metadata{
							Command:   "uvx",
							Args:      []string{"mcp-server-git", "--repository", "test"},
							Env:       map[string]string{},
							RuntimeID: "python-server",
						},
					},
				},
			},
		},
		{
			Name: "Scoped_Package_With_Version",
			Path: "test/mcp.json",
			Content: `{
				"mcpServers": {
					"scoped-server": {
						"command": "npx",
						"args": [
							"-y",
							"@scope/pkg@1.2.3"
						]
					}
				}
			}`,
			WantInventory: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:      "@scope/pkg",
						Version:   "1.2.3",
						PURLType:  purl.TypeNPM,
						Locations: []string{"test/mcp.json"},
						Metadata: &metadata.Metadata{
							Command:   "npx",
							Args:      []string{"-y", "@scope/pkg@1.2.3"},
							Env:       map[string]string{},
							RuntimeID: "scoped-server",
						},
					},
				},
			},
		},
		{
			Name: "Normal_Package_With_Version",
			Path: "test/mcp.json",
			Content: `{
				"mcpServers": {
					"normal-server": {
						"command": "npx",
						"args": ["pkg@1.2.3"]
					}
				}
			}`,
			WantInventory: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:      "pkg",
						Version:   "1.2.3",
						PURLType:  purl.TypeNPM,
						Locations: []string{"test/mcp.json"},
						Metadata: &metadata.Metadata{
							Command:   "npx",
							Args:      []string{"pkg@1.2.3"},
							Env:       map[string]string{},
							RuntimeID: "normal-server",
						},
					},
				},
			},
		},
		{
			Name: "Vulnerable_mcp_json_testdata",
			Path: "test/mcp.json",
			Content: `{
			"mcpServers": {
				"vulnerable-filesystem": {
					"command": "npx",
					"args": [
						"-y",
						"@modelcontextprotocol/server-filesystem@0.6.2",
						"/tmp/allowed_test_dir"
					],
					"env": {}
				},
				"vulnerable-python-git": {
					"command": "uvx",
					"args": [
						"mcp-server-git@2025.12.17",
						"--repository",
						"/tmp/safe_repo"
					],
					"env": {}
				}
			}
			}`,
			WantInventory: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:      "@modelcontextprotocol/server-filesystem",
						Version:   "0.6.2",
						PURLType:  purl.TypeNPM,
						Locations: []string{"test/mcp.json"},
						Metadata: &metadata.Metadata{
							Command:   "npx",
							Args:      []string{"-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/tmp/allowed_test_dir"},
							Env:       map[string]string{},
							RuntimeID: "vulnerable-filesystem",
						},
					},
					{
						Name:      "mcp-server-git",
						Version:   "2025.12.17",
						PURLType:  purl.TypePyPi,
						Locations: []string{"test/mcp.json"},
						Metadata: &metadata.Metadata{
							Command:   "uvx",
							Args:      []string{"mcp-server-git@2025.12.17", "--repository", "/tmp/safe_repo"},
							Env:       map[string]string{},
							RuntimeID: "vulnerable-python-git",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			e, err := config.New(nil)
			if err != nil {
				t.Fatalf("config.New() error = %v", err)
			}

			input := &filesystem.ScanInput{
				Path:   tt.Path,
				Reader: strings.NewReader(tt.Content),
			}

			got, err := e.Extract(context.Background(), input)
			if err != nil {
				t.Fatalf("Extract() error = %v", err)
			}

			sortPackages := cmpopts.SortSlices(func(a, b *extractor.Package) bool {
				return a.Name < b.Name
			})

			if diff := cmp.Diff(tt.WantInventory, got, sortPackages); diff != "" {
				t.Errorf("Extract() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
