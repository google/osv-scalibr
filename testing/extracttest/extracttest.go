// Package extracttest provides structures to help create tabular tests for extractors.
package extracttest

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/internal/errormatcher"
	"github.com/google/osv-scalibr/testing/internal/pkgmatcher"
)

type ScanInputMockConfig struct {
	Path string
	// FakeScanRoot allows you to set a custom scanRoot, can be relative or absolute,
	// and will be translated to an absolute path
	FakeScanRoot string
	FakeFileInfo *fakefs.FakeFileInfo
}

type TestTableEntry struct {
	Name              string
	InputConfig       ScanInputMockConfig
	WantInventory     []*extractor.Inventory
	WantErrIs         error
	WantErrContaining string
}

// ExtractionTester tests common properties of a extractor, and returns the raw values from running extract
func ExtractionTester(t *testing.T, extractor filesystem.Extractor, tt TestTableEntry) ([]*extractor.Inventory, error) {
	t.Helper()

	wrapper := generateScanInputMock(t, tt.InputConfig)
	got, err := extractor.Extract(context.Background(), &wrapper.ScanInput)
	wrapper.close()
	if tt.WantErrIs != nil {
		errormatcher.ExpectErrIs(t, err, tt.WantErrIs)
	}
	if tt.WantErrContaining != "" {
		errormatcher.ExpectErrContaining(t, err, tt.WantErrContaining)
	}

	if tt.WantErrContaining == "" && tt.WantErrIs == nil && err != nil {
		t.Errorf("Got error when expecting none: '%s'", err)
	} else {
		pkgmatcher.ExpectPackages(t, got, tt.WantInventory)
	}

	return got, err
}

type scanInputWrapper struct {
	fileHandle *os.File
	ScanInput  filesystem.ScanInput
}

func (siw scanInputWrapper) close() {
	siw.fileHandle.Close()
}

// generateScanInputMock will try to open the file locally, and fail if the file doesn't exist
func generateScanInputMock(t *testing.T, config ScanInputMockConfig) scanInputWrapper {
	t.Helper()

	var scanRoot string
	if filepath.IsAbs(config.FakeScanRoot) {
		scanRoot = config.FakeScanRoot
	} else {
		workingDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("Can't get working directory because '%s'", workingDir)
		}
		scanRoot = filepath.Join(workingDir, config.FakeScanRoot)
	}

	f, err := os.Open(filepath.Join(scanRoot, config.Path))
	if err != nil {
		t.Fatalf("Can't open test fixture '%s' because '%s'", config.Path, err)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("Can't stat test fixture '%s' because '%s'", config.Path, err)
	}

	return scanInputWrapper{
		fileHandle: f,
		ScanInput: filesystem.ScanInput{
			FS:     os.DirFS(scanRoot).(scalibrfs.FS),
			Path:   config.Path,
			Root:   scanRoot,
			Reader: f,
			Info:   info,
		},
	}
}
