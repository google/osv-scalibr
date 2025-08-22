//go:build !windows

package winget

import (
	"context"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestFileRequired_NonWindows(t *testing.T) {
	extractor := NewDefault()
	testPath := "/some/path/installed.db"
	api := simplefileapi.New(testPath, fakefs.FakeFileInfo{
		FileName: filepath.Base(testPath),
		FileMode: fs.ModePerm,
		FileSize: 1000,
	})

	got := extractor.FileRequired(api)
	if got != false {
		t.Errorf("FileRequired() = %v, want false on non-Windows", got)
	}
}

func TestExtract_NonWindows(t *testing.T) {
	extractor := NewDefault()
	
	// Use a dummy input since Extract should fail immediately with platform error
	input := &filesystem.ScanInput{
		Path: "test.db",
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

