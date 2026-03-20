package config_test

import (
	"context"
	"errors"
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
						Name:     "@modelcontextprotocol/server-filesystem",
						Version:  "",
						PURLType: purl.TypeNPM,
						Location: extractor.LocationFromPath("test/mcp.json"),
						Metadata: &metadata.Metadata{
							Command:   "npx",
							Args:      []string{"-y", "@modelcontextprotocol/server-filesystem", "/path/to/allowed/files"},
							Env:       map[string]string{"API_KEY": "[REDACTED]"},
							RuntimeID: "filesystem",
						},
					},
					{
						Name:     "mcp-server-git",
						PURLType: purl.TypePyPi,
						Location: extractor.LocationFromPath("test/mcp.json"),
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
						Name:     "@scope/pkg",
						Version:  "1.2.3",
						PURLType: purl.TypeNPM,
						Location: extractor.LocationFromPath("test/mcp.json"),
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
						Name:     "pkg",
						Version:  "1.2.3",
						PURLType: purl.TypeNPM,
						Location: extractor.LocationFromPath("test/mcp.json"),
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
						Name:     "@modelcontextprotocol/server-filesystem",
						Version:  "0.6.2",
						PURLType: purl.TypeNPM,
						Location: extractor.LocationFromPath("test/mcp.json"),
						Metadata: &metadata.Metadata{
							Command:   "npx",
							Args:      []string{"-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/tmp/allowed_test_dir"},
							Env:       map[string]string{},
							RuntimeID: "vulnerable-filesystem",
						},
					},
					{
						Name:     "mcp-server-git",
						Version:  "2025.12.17",
						PURLType: purl.TypePyPi,
						Location: extractor.LocationFromPath("test/mcp.json"),
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
		{
			Name: "UVX_With_Python_Flag",
			Path: "test/mcp.json",
			Content: `{
				"mcpServers": {
					"aws-documentation": {
						"command": "uvx",
						"args": ["--python", "3.13", "awslabs.aws-documentation-mcp-server"],
						"env": {
							"FASTMCP_LOG_LEVEL": "ERROR",
							"AWS_DOCUMENTATION_PARTITION": "aws"
						}
					}
				}
			}`,
			WantInventory: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "awslabs.aws-documentation-mcp-server",
						Version:  "",
						PURLType: purl.TypePyPi,
						Location: extractor.LocationFromPath("test/mcp.json"),
						Metadata: &metadata.Metadata{
							Command:   "uvx",
							Args:      []string{"--python", "3.13", "awslabs.aws-documentation-mcp-server"},
							Env:       map[string]string{"FASTMCP_LOG_LEVEL": "[REDACTED]", "AWS_DOCUMENTATION_PARTITION": "[REDACTED]"},
							RuntimeID: "aws-documentation",
						},
					},
				},
			},
		},
		{
			Name: "Pipx_With_Run_Command_And_Flags",
			Path: "test/mcp.json",
			Content: `{
                "mcpServers": {
                    "python-pipx-server": {
                        "command": "pipx",
                        "args": ["run", "--python", "3.12", "my-transient-server@2.5.0"]
                    }
                }
            }`,
			WantInventory: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "my-transient-server",
						Version:  "2.5.0",
						PURLType: purl.TypePyPi,
						Location: extractor.LocationFromPath("test/mcp.json"),
						Metadata: &metadata.Metadata{
							Command:   "pipx",
							Args:      []string{"run", "--python", "3.12", "my-transient-server@2.5.0"},
							Env:       map[string]string{},
							RuntimeID: "python-pipx-server",
						},
					},
				},
			},
		},
		{
			Name: "Uv_Tool_Run_Command",
			Path: "test/mcp.json",
			Content: `{
				"mcpServers": {
					"uv-tool-server": {
						"command": "uv",
						"args": ["tool", "run", "--python", "3.12", "my-uv-server@1.0"]
					}
				}
			}`,
			WantInventory: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "my-uv-server",
						Version:  "1.0",
						PURLType: purl.TypePyPi,
						Location: extractor.LocationFromPath("test/mcp.json"),
						Metadata: &metadata.Metadata{
							Command:   "uv",
							Args:      []string{"tool", "run", "--python", "3.12", "my-uv-server@1.0"},
							Env:       map[string]string{},
							RuntimeID: "uv-tool-server",
						},
					},
				},
			},
		},
		{
			Name: "Go_Run_Remote_Module",
			Path: "test/mcp.json",
			Content: `{
				"mcpServers": {
					"remote-go-server": {
						"command": "go",
						"args": ["run", "github.com/mark3labs/mcp-go/examples/ping@v0.1.0"]
					}
				}
			}`,
			WantInventory: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "github.com/mark3labs/mcp-go/examples/ping",
						Version:  "v0.1.0",
						PURLType: purl.TypeGolang,
						Location: extractor.LocationFromPath("test/mcp.json"),
						Metadata: &metadata.Metadata{
							Command:   "go",
							Args:      []string{"run", "github.com/mark3labs/mcp-go/examples/ping@v0.1.0"},
							Env:       map[string]string{},
							RuntimeID: "remote-go-server",
						},
					},
				},
			},
		},
		{
			Name: "Go_Run_Local_File",
			Path: "test/mcp.json",
			Content: `{
				"mcpServers": {
					"local-go-server": {
						"command": "go",
						"args": ["run", "main.go"]
					}
				}
			}`,
			WantInventory: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "mcp-server/local-go-server",
						Version:  "",
						PURLType: purl.TypeGeneric,
						Location: extractor.LocationFromPath("test/mcp.json"),
						Metadata: &metadata.Metadata{
							Command:   "go",
							Args:      []string{"run", "main.go"},
							Env:       map[string]string{},
							RuntimeID: "local-go-server",
						},
					},
				},
			},
		},
		{
			Name: "NPX_With_Node_Arg_Schema",
			Path: "test/mcp.json",
			Content: `{
				"mcpServers": {
					"complex-npx": {
						"command": "npx",
						"args": ["--node-arg", "--inspect", "-y", "@some/pkg@2.0.0"]
					}
				}
			}`,
			WantInventory: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "@some/pkg",
						Version:  "2.0.0",
						PURLType: purl.TypeNPM,
						Location: extractor.LocationFromPath("test/mcp.json"),
						Metadata: &metadata.Metadata{
							Command:   "npx",
							Args:      []string{"--node-arg", "--inspect", "-y", "@some/pkg@2.0.0"},
							Env:       map[string]string{},
							RuntimeID: "complex-npx",
						},
					},
				},
			},
		},
		{
			Name: "UVX_With_Equals_Sign_And_Unknown_Bool",
			Path: "test/mcp.json",
			Content: `{
				"mcpServers": {
					"complex-uvx": {
						"command": "uvx",
						"args": ["--verbose", "--python=3.13", "mypackage@1.0"]
					}
				}
			}`,
			WantInventory: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "mypackage",
						Version:  "1.0",
						PURLType: purl.TypePyPi,
						Location: extractor.LocationFromPath("test/mcp.json"),
						Metadata: &metadata.Metadata{
							Command:   "uvx",
							Args:      []string{"--verbose", "--python=3.13", "mypackage@1.0"},
							Env:       map[string]string{},
							RuntimeID: "complex-uvx",
						},
					},
				},
			},
		},
		{
			Name: "Docker_Run_With_Tag_And_Flags",
			Path: "test/mcp.json",
			Content: `{
				"mcpServers": {
					"docker-server": {
						"command": "docker",
						"args": ["run", "-i", "--rm", "-e", "API_KEY=123", "-v", "/local:/container", "mcp/sqlite-server:1.2.0"]
					}
				}
			}`,
			WantInventory: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "mcp/sqlite-server",
						Version:  "1.2.0",
						PURLType: purl.TypeDocker,
						Location: extractor.LocationFromPath("test/mcp.json"),
						Metadata: &metadata.Metadata{
							Command:   "docker",
							Args:      []string{"run", "-i", "--rm", "-e", "API_KEY=123", "-v", "/local:/container", "mcp/sqlite-server:1.2.0"},
							Env:       map[string]string{},
							RuntimeID: "docker-server",
						},
					},
				},
			},
		},
		{
			Name: "Docker_Run_With_Registry_Port_No_Tag",
			Path: "test/mcp.json",
			Content: `{
				"mcpServers": {
					"custom-registry-server": {
						"command": "docker",
						"args": ["run", "localhost:5000/my-company/custom-mcp"]
					}
				}
			}`,
			WantInventory: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "localhost:5000/my-company/custom-mcp",
						Version:  "",
						PURLType: purl.TypeDocker,
						Location: extractor.LocationFromPath("test/mcp.json"),
						Metadata: &metadata.Metadata{
							Command:   "docker",
							Args:      []string{"run", "localhost:5000/my-company/custom-mcp"},
							Env:       map[string]string{},
							RuntimeID: "custom-registry-server",
						},
					},
				},
			},
		},
		{
			Name: "Generic_Fallback_Command",
			Path: "test/mcp.json",
			Content: `{
				"mcpServers": {
					"custom-go-server": {
						"command": "go",
						"args": ["run", "main.go"]
					}
				}
			}`,
			WantInventory: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "mcp-server/custom-go-server",
						Version:  "",
						PURLType: purl.TypeGeneric,
						Location: extractor.LocationFromPath("test/mcp.json"),
						Metadata: &metadata.Metadata{
							Command:   "go",
							Args:      []string{"run", "main.go"},
							Env:       map[string]string{},
							RuntimeID: "custom-go-server",
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

func TestExtractContextCancellation(t *testing.T) {
	e, err := config.New(nil)
	if err != nil {
		t.Fatalf("config.New() error = %v", err)
	}

	content := `{
		"mcpServers": {
			"server1": {"command": "npx", "args": ["pkg1"]},
			"server2": {"command": "npx", "args": ["pkg2"]}
		}
	}`

	input := &filesystem.ScanInput{
		Path:   "test/mcp.json",
		Reader: strings.NewReader(content),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = e.Extract(ctx, input)
	if err == nil {
		t.Fatal("Extract() expected error due to canceled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Extract() error = %v; want %v", err, context.Canceled)
	}
}
