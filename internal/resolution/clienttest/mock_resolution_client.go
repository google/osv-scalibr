package clienttest

import (
	"os"
	"strings"
	"testing"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/schema"
	"github.com/google/osv-scalibr/internal/resolution/client"
	"gopkg.in/yaml.v3"
)

type ResolutionUniverse struct {
	System string `yaml:"system"`
	Schema string `yaml:"schema"`
}

type mockDependencyClient struct {
	*resolve.LocalClient
}

func (mdc mockDependencyClient) AddRegistries(_ []client.Registry) error { return nil }

func NewMockResolutionClient(t *testing.T, universeYAML string) client.DependencyClient {
	t.Helper()
	f, err := os.Open(universeYAML)
	if err != nil {
		t.Fatalf("failed opening mock universe: %v", err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)

	var universe ResolutionUniverse
	if err := dec.Decode(&universe); err != nil {
		t.Fatalf("failed decoding mock universe: %v", err)
	}

	var sys resolve.System
	switch strings.ToLower(universe.System) {
	case "npm":
		sys = resolve.NPM
	case "maven":
		sys = resolve.Maven
	default:
		t.Fatalf("unknown ecosystem in universe: %s", universe.System)
	}

	// schema needs a strict tab indentation, which is awkward to do within the YAML.
	// Replace double space from yaml with single tab
	universe.Schema = strings.ReplaceAll(universe.Schema, "  ", "\t")
	sch, err := schema.New(universe.Schema, sys)
	if err != nil {
		t.Fatalf("failed parsing schema: %v", err)
	}

	return mockDependencyClient{sch.NewClient()}
}
