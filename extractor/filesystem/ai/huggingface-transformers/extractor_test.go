package aimodels

import (
	"context"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// FakeFileAPI mocks filesystem.FileAPI for testing.
type FakeFileAPI struct {
	filesystem.FileAPI
	path string
}

// Path returns the mock file path.
func (f FakeFileAPI) Path() string { return f.path }

// fakeScanInput is a helper to create filesystem.ScanInput for testing.
func fakeScanInput(path, content string) *filesystem.ScanInput {
	return &filesystem.ScanInput{
		Path:   path,
		Reader: strings.NewReader(content),
	}
}

func TestExtractor_Metadata(t *testing.T) {
	e := Extractor{}

	t.Run("Name_ReturnsCorrectValue", func(t *testing.T) {
		got := e.Name()
		want := "ai/huggingface-transformers"
		if got != want {
			t.Errorf("Name() = %q, want %q", got, want)
		}
	})

	t.Run("Version_ReturnsCorrectValue", func(t *testing.T) {
		got := e.Version()
		if got != 1 {
			t.Errorf("Version() = %d, want 1", got)
		}
	})

	t.Run("Requirements_ReturnsNonNil", func(t *testing.T) {
		got := e.Requirements()
		if got == nil {
			t.Error("Requirements() returned nil")
		}
	})

	t.Run("ImplementsFilesystemExtractorInterface", func(t *testing.T) {
		var _ filesystem.Extractor = Extractor{}
		var _ filesystem.Extractor = &Extractor{}
	})
}

func TestExtractor_FileRequired(t *testing.T) {
	e := Extractor{}

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"config.json root", "config.json", true},
		{"config.json nested", "models/bert/config.json", true},
		{"adapter_config.json root", "adapter_config.json", true},
		{"README.md ignored", "README.md", false},
		{"model.safetensors ignored", "model.safetensors", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.FileRequired(FakeFileAPI{path: tt.path})
			if got != tt.expected {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	e := Extractor{}

	t.Run("Success_ValidConfig", func(t *testing.T) {
		content := `{"transformers_version":"4.31.0","model_type":"bert"}`
		path := "models/bert/config.json"
		input := fakeScanInput(path, content)

		inv, err := e.Extract(context.Background(), input)
		if err != nil {
			t.Fatalf("Extract() error = %v", err)
		}
		if len(inv.Packages) != 1 {
			t.Fatalf("len(Packages) = %d, want 1", len(inv.Packages))
		}

		p := inv.Packages[0]
		if p.Name != "transformers" || p.Version != "4.31.0" {
			t.Errorf("Got %s@%s, want transformers@4.31.0", p.Name, p.Version)
		}
		if p.PURLType != purl.TypePyPi {
			t.Errorf("PURLType = %q, want %q", p.PURLType, purl.TypePyPi)
		}
		if p.Location.PathOrEmpty() != path {
			t.Errorf("Location mismatch")
		}

		purlObj := p.PURL()
		if purlObj == nil || purlObj.String() != "pkg:pypi/transformers@4.31.0" {
			t.Errorf("PURL generation failed")
		}
	})

	t.Run("EmptyVersion_ReturnsEmpty", func(t *testing.T) {
		content := `{"model_type":"bert"}`
		input := fakeScanInput("config.json", content)
		inv, err := e.Extract(context.Background(), input)
		if err != nil || len(inv.Packages) != 0 {
			t.Errorf("Expected empty inventory for missing version")
		}
	})

	t.Run("InvalidJSON_ReturnsEmpty", func(t *testing.T) {
		input := fakeScanInput("config.json", `{"invalid":}`)
		inv, err := e.Extract(context.Background(), input)
		if err != nil || len(inv.Packages) != 0 {
			t.Errorf("Expected empty inventory for invalid JSON")
		}
	})
}

func TestExtractor_FullWorkflow(t *testing.T) {
	e := Extractor{}
	content := `{"architectures":["BertForMaskedLM"],"model_type":"bert","transformers_version":"4.31.0"}`
	input := fakeScanInput("bert/config.json", content)

	inv, err := e.Extract(context.Background(), input)
	if err != nil || len(inv.Packages) != 1 {
		t.Fatalf("Expected 1 package")
	}

	pkg := inv.Packages[0]
	if pkg.Name != "transformers" || pkg.Version != "4.31.0" {
		t.Errorf("Package mismatch")
	}
	if pkg.PURL().String() != "pkg:pypi/transformers@4.31.0" {
		t.Errorf("PURL mismatch")
	}
}

func BenchmarkExtractor_FileRequired(b *testing.B) {
	e := Extractor{}
	api := FakeFileAPI{path: "models/bert/config.json"}
	for range b.N {
		_ = e.FileRequired(api)
	}
}

func BenchmarkExtractor_Extract(b *testing.B) {
	e := Extractor{}
	content := `{"transformers_version":"4.31.0"}`
	input := fakeScanInput("config.json", content)
	ctx := context.Background()
	for range b.N {
		_, _ = e.Extract(ctx, input)
	}
}
