package aspect_test

import (
	"testing"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem/bazel/aspect"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			name:      "empty",
			inputPath: "",
			want:      false,
		},
		{
			name:      "workspace",
			inputPath: "WORKSPACE",
			want:      true,
		},
		{
			name:      "workspace.bazel",
			inputPath: "WORKSPACE.bazel",
			want:      true,
		},
		{
			name:      "module.bazel",
			inputPath: "MODULE.bazel",
			want:      true,
		},
		{
			name:      "build",
			inputPath: "BUILD",
			want:      false,
		},
		{
			name:      "nested workspace",
			inputPath: "path/to/my/WORKSPACE",
			want:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := aspect.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("aspect.New() error: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_NameVersion(t *testing.T) {
	e, err := aspect.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("aspect.New() error: %v", err)
	}
	if got := e.Name(); got != aspect.Name {
		t.Errorf("Name() = %v, want %v", got, aspect.Name)
	}
	if got := e.Version(); got != 0 {
		t.Errorf("Version() = %v, want %v", got, 0)
	}
}

func TestExtractor_Requirements(t *testing.T) {
	e, err := aspect.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("aspect.New() error: %v", err)
	}
	reqs := e.Requirements()
	if !reqs.RunningSystem {
		t.Errorf("Requirements().RunningSystem = %v, want %v", reqs.RunningSystem, true)
	}
	if !reqs.DirectFS {
		t.Errorf("Requirements().DirectFS = %v, want %v", reqs.DirectFS, true)
	}
}
