package aimodels

import (
	"context"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/purl"
)

type FakeFileAPI struct {
	filesystem.FileAPI
	path string
}

func (f FakeFileAPI) Path() string { return f.path }

func fakeScanInput(path, content string) *filesystem.ScanInput {
	return &filesystem.ScanInput{Path: path, Reader: strings.NewReader(content)}
}

func TestExtractor_Metadata(t *testing.T) {
	e := Extractor{}
	if got := e.Name(); got != "ai/huggingface-transformers" {
		t.Errorf("Name() = %q", got)
	}
	if got := e.Version(); got != 1 {
		t.Errorf("Version() = %d", got)
	}
	if e.Requirements() == nil {
		t.Error("Requirements() returned nil")
	}
	var _ filesystem.Extractor = Extractor{}
}

func TestExtractor_FileRequired(t *testing.T) {
	e := Extractor{}
	tests := []struct{ path string; want bool }{
		{"config.json", true}, {"adapter_config.json", true},
		{"README.md", false}, {"model.safetensors", false},
	}
	for _, tt := range tests {
		if got := e.FileRequired(FakeFileAPI{path: tt.path}); got != tt.want {
			t.Errorf("FileRequired(%q) = %v", tt.path, got)
		}
	}
}

func TestExtractor_Extract(t *testing.T) {
	e := Extractor{}
	t.Run("valid", func(t *testing.T) {
		input := fakeScanInput("c.json", `{"transformers_version":"4.31.0"}`)
		inv, err := e.Extract(context.Background(), input)
		if err != nil || len(inv.Packages) != 1 {
			t.Fatalf("expected 1 package")
		}
		p := inv.Packages[0]
		if p.Name != "transformers" || p.Version != "4.31.0" {
			t.Errorf("got %s@%s", p.Name, p.Version)
		}
		if p.PURL().String() != "pkg:pypi/transformers@4.31.0" {
			t.Errorf("PURL mismatch")
		}
	})
	t.Run("empty", func(t *testing.T) {
		input := fakeScanInput("c.json", `{"model_type":"bert"}`)
		inv, _ := e.Extract(context.Background(), input)
		if len(inv.Packages) != 0 {
			t.Error("expected empty inventory")
		}
	})
}

func TestExtractor_FullWorkflow(t *testing.T) {
	e := Extractor{}
	input := fakeScanInput("bert/c.json", `{"model_type":"bert","transformers_version":"4.31.0"}`)
	inv, err := e.Extract(context.Background(), input)
	if err != nil || len(inv.Packages) != 1 {
		t.Fatalf("expected 1 package")
	}
	pkg := inv.Packages[0]
	checks := []struct{ name string; got, want any }{
		{"Name", pkg.Name, "transformers"},
		{"Version", pkg.Version, "4.31.0"},
		{"PURLType", pkg.PURLType, purl.TypePyPi},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, c.got, c.want)
		}
	}
}

func BenchmarkExtractor_FileRequired(b *testing.B) {
	e := Extractor{}
	api := FakeFileAPI{path: "c.json"}
	for range b.N {
		_ = e.FileRequired(api)
	}
}

func BenchmarkExtractor_Extract(b *testing.B) {
	e := Extractor{}
	input := fakeScanInput("c.json", `{"transformers_version":"4.31.0"}`)
	ctx := context.Background()
	for range b.N {
		_, _ = e.Extract(ctx, input)
	}
}
