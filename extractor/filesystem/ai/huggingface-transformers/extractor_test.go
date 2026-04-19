package aimodels

import (
	"context"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// FakeFileAPI mocks the filesystem.FileAPI interface for testing.
type FakeFileAPI struct {
	path string
	filesystem.FileAPI
}

// Path returns the mock file path.
func (f FakeFileAPI) Path() string { return f.path }

// fakeScanInput is a helper function to create a filesystem.ScanInput for testing.
func fakeScanInput(path, content string) *filesystem.ScanInput {
	return &filesystem.ScanInput{
		Path:   path,
		Reader: strings.NewReader(content),
	}
}

func TestExtractor_Metadata(t *testing.T) {
	e := Extractor{}

	t.Run("Name_ReturnsCorrectValue", func(t *testing.T) {
		if got := e.Name(); got != "ai/huggingface-transformers" {
			t.Errorf("Name() = %q, want %q", got, "ai/huggingface-transformers")
		}
	})

	t.Run("Version_ReturnsCorrectValue", func(t *testing.T) {
		if got := e.Version(); got != 1 {
			t.Errorf("Version() = %d, want 1", got)
		}
	})

	t.Run("Requirements_ReturnsNonNil", func(t *testing.T) {
		got := e.Requirements()
		if got == nil {
			t.Error("Requirements() returned nil, want non-nil *plugin.Capabilities")
		}
		want := &plugin.Capabilities{}
		if got.Network != want.Network || got.OS != want.OS {
			t.Errorf("Requirements() = %+v, want empty capabilities", got)
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
		{"config.json deep", "a/b/c/config.json", true},
		{"adapter_config.json root", "adapter_config.json", true},
		{"adapter_config.json nested", "peft/adapter_config.json", true},
		{"README.md ignored", "README.md", false},
		{"model.safetensors ignored", "model.safetensors", false},
		{"config.json.bak ignored", "config.json.bak", false},
		{"empty path", "", false},
		{"just extension", ".json", false},
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
		content := `{"transformers_version": "4.31.0", "model_type": "bert"}`
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
		if p.Name != "transformers" {
			t.Errorf("Name = %q, want %q", p.Name, "transformers")
		}
		if p.Version != "4.31.0" {
			t.Errorf("Version = %q, want %q", p.Version, "4.31.0")
		}
		if p.PURLType != purl.TypePyPi {
			t.Errorf("PURLType = %q, want %q", p.PURLType, purl.TypePyPi)
		}
		if p.Location.PathOrEmpty() != path {
			t.Errorf("Location = %q, want %q", p.Location.PathOrEmpty(), path)
		}

		purlObj := p.PURL()
		if purlObj == nil {
			t.Fatal("PURL() returned nil")
		}
		if got := purlObj.String(); got != "pkg:pypi/transformers@4.31.0" {
			t.Errorf("PURL.String() = %q, want %q", got, "pkg:pypi/transformers@4.31.0")
		}
	})

	t.Run("Success_AdapterConfig", func(t *testing.T) {
		content := `{"transformers_version": "4.35.2", "base_model_name_or_path": "meta-llama/Llama-2-7b"}`
		input := fakeScanInput("peft/adapter_config.json", content)

		inv, err := e.Extract(context.Background(), input)
		if err != nil {
			t.Fatalf("Extract() error = %v", err)
		}
		if len(inv.Packages) != 1 {
			t.Fatalf("len(Packages) = %d, want 1", len(inv.Packages))
		}
		if inv.Packages[0].Version != "4.35.2" {
			t.Errorf("Version = %q, want %q", inv.Packages[0].Version, "4.35.2")
		}
	})

	t.Run("EmptyVersion_ReturnsEmptyInventory", func(t *testing.T) {
		content := `{"model_type": "bert", "architectures": ["BertModel"]}`
		input := fakeScanInput("config.json", content)

		inv, err := e.Extract(context.Background(), input)
		if err != nil {
			t.Fatalf("Extract() error = %v", err)
		}
		if len(inv.Packages) != 0 {
			t.Errorf("len(Packages) = %d, want 0", len(inv.Packages))
		}
	})

	t.Run("MissingTransformersVersion_ReturnsEmptyInventory", func(t *testing.T) {
		content := `{"some_other_field": "value"}`
		input := fakeScanInput("config.json", content)

		inv, err := e.Extract(context.Background(), input)
		if err != nil {
			t.Fatalf("Extract() error = %v", err)
		}
		if len(inv.Packages) != 0 {
			t.Errorf("len(Packages) = %d, want 0", len(inv.Packages))
		}
	})

	t.Run("InvalidJSON_ReturnsEmptyInventory_NoError", func(t *testing.T) {
		content := `{"invalid": json, "broken": }`
		input := fakeScanInput("config.json", content)

		inv, err := e.Extract(context.Background(), input)
		if err != nil {
			t.Errorf("Extract() error = %v, want nil", err)
		}
		if len(inv.Packages) != 0 {
			t.Errorf("len(Packages) = %d, want 0", len(inv.Packages))
		}
	})

	t.Run("EmptyFile_ReturnsEmptyInventory", func(t *testing.T) {
		input := fakeScanInput("config.json", "")
		inv, err := e.Extract(context.Background(), input)
		if err != nil {
			t.Fatalf("Extract() error = %v", err)
		}
		if len(inv.Packages) != 0 {
			t.Errorf("len(Packages) = %d, want 0", len(inv.Packages))
		}
	})

	t.Run("WhitespaceOnly_ReturnsEmptyInventory", func(t *testing.T) {
		input := fakeScanInput("config.json", "   \n\t  ")
		inv, err := e.Extract(context.Background(), input)
		if err != nil {
			t.Fatalf("Extract() error = %v", err)
		}
		if len(inv.Packages) != 0 {
			t.Errorf("len(Packages) = %d, want 0", len(inv.Packages))
		}
	})

	t.Run("VersionWithPrerelease", func(t *testing.T) {
		content := `{"transformers_version": "4.31.0.dev0"}`
		input := fakeScanInput("config.json", content)

		inv, err := e.Extract(context.Background(), input)
		if err != nil {
			t.Fatalf("Extract() error = %v", err)
		}
		if len(inv.Packages) != 1 {
			t.Fatalf("len(Packages) = %d, want 1", len(inv.Packages))
		}
		if inv.Packages[0].Version != "4.31.0.dev0" {
			t.Errorf("Version = %q, want %q", inv.Packages[0].Version, "4.31.0.dev0")
		}
		if got := inv.Packages[0].PURL().String(); got != "pkg:pypi/transformers@4.31.0.dev0" {
			t.Errorf("PURL = %q, want %q", got, "pkg:pypi/transformers@4.31.0.dev0")
		}
	})

	t.Run("ContextCancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		content := `{"transformers_version": "4.31.0"}`
		input := fakeScanInput("config.json", content)

		inv, err := e.Extract(ctx, input)
		if err != nil {
			t.Fatalf("Extract() error = %v", err)
		}
		if len(inv.Packages) != 1 {
			t.Errorf("len(Packages) = %d, want 1", len(inv.Packages))
		}
	})
}

func TestExtractor_FullWorkflow(t *testing.T) {
	e := Extractor{}

	realisticConfig := `{
		"architectures": ["BertForMaskedLM"],
		"model_type": "bert",
		"transformers_version": "4.31.0",
		"vocab_size": 30522,
		"hidden_size": 768,
		"num_attention_heads": 12
	}`

	input := fakeScanInput("bert-base-uncased/config.json", realisticConfig)
	inv, err := e.Extract(context.Background(), input)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	if len(inv.Packages) != 1 {
		t.Fatalf("Expected 1 package, got %d", len(inv.Packages))
	}

	pkg := inv.Packages[0]
	checks := []struct {
		name     string
		got      interface{}
		expected interface{}
	}{
		{"Name", pkg.Name, "transformers"},
		{"Version", pkg.Version, "4.31.0"},
		{"PURLType", pkg.PURLType, purl.TypePyPi},
		{"Location", pkg.Location.PathOrEmpty(), "bert-base-uncased/config.json"},
	}

	for _, c := range checks {
		if c.got != c.expected {
			t.Errorf("%s: got %v, want %v", c.name, c.got, c.expected)
		}
	}

	purlStr := pkg.PURL().String()
	expectedPURL := "pkg:pypi/transformers@4.31.0"
	if purlStr != expectedPURL {
		t.Errorf("PURL.String() = %q, want %q", purlStr, expectedPURL)
	}
}

func BenchmarkExtractor_FileRequired(b *testing.B) {
	e := Extractor{}
	api := FakeFileAPI{path: "models/bert/config.json"}
	for i := 0; i < b.N; i++ {
		_ = e.FileRequired(api)
	}
}

func BenchmarkExtractor_Extract(b *testing.B) {
	e := Extractor{}
	content := `{"transformers_version": "4.31.0"}`
	input := fakeScanInput("config.json", content)
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		_, _ = e.Extract(ctx, input)
	}
}
