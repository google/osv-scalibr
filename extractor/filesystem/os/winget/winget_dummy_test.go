//go:build !windows

package winget

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
)

func TestFileRequired_NonWindows(t *testing.T) {
	extractor := NewDefault()
	api := &mockFileAPI{path: "/some/path/installed.db"}

	got := extractor.FileRequired(api)
	if got != false {
		t.Errorf("FileRequired() = %v, want false on non-Windows", got)
	}
}

func TestExtract_NonWindows(t *testing.T) {
	extractor := NewDefault()
	input := &filesystem.ScanInput{
		Path:   "test.db",
		Reader: strings.NewReader(""),
	}

	_, err := extractor.Extract(context.Background(), input)
	if err == nil {
		t.Error("Expected error on non-Windows platform")
	}

	expectedErr := "only supported on Windows"
	if err.Error() != expectedErr {
		t.Errorf("Extract() error = %v, want %v", err.Error(), expectedErr)
	}
}

func TestExtractorInterface_NonWindows(t *testing.T) {
	extractor := NewDefault()

	if extractor.Name() != Name {
		t.Errorf("Name() = %v, want %v", extractor.Name(), Name)
	}

	if extractor.Version() != 0 {
		t.Errorf("Version() = %v, want %v", extractor.Version(), 0)
	}

	caps := extractor.Requirements()
	if caps.OS != 2 { // plugin.OSWindows = 2
		t.Errorf("Requirements().OS = %v, want Windows (2)", caps.OS)
	}
}

// mockFileAPI implements filesystem.FileAPI for testing
type mockFileAPI struct {
	path string
}

func (m *mockFileAPI) Path() string               { return m.path }
func (m *mockFileAPI) Stat() (os.FileInfo, error) { return nil, nil }
