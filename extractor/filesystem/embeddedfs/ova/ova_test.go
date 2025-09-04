package ova_test

import (
	"archive/tar"
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/ova"
	"github.com/google/osv-scalibr/purl"
	"io/fs"
)

// testFileInfo implements filesystem.FileAPI for FileRequired tests.
type testFileInfo struct {
	path string
	size int64
}

func (i *testFileInfo) Path() string { return i.path }
func (i *testFileInfo) Stat() (fs.FileInfo, error) {
	return &testFileInfoImpl{path: i.path, size: i.size}, nil
}

// testFileInfoImpl implements io/fs.FileInfo for ScanInput.Info.
type testFileInfoImpl struct {
	path string
	size int64
}

func (i *testFileInfoImpl) Name() string {
	return filepath.Base(i.path)
}

func (i *testFileInfoImpl) Size() int64 {
	return i.size
}

func (i *testFileInfoImpl) Mode() fs.FileMode {
	return 0644
}

func (i *testFileInfoImpl) ModTime() time.Time {
	return time.Now()
}

func (i *testFileInfoImpl) IsDir() bool {
	return false
}

func (i *testFileInfoImpl) Sys() any {
	return nil
}

// TestOVAExtractorFileRequired tests the FileRequired method.
func TestOVAExtractorFileRequired(t *testing.T) {
	extractor := ova.New()
	tests := []struct {
		path string
		want bool
	}{
		{path: "test.ova", want: true},
		{path: "test.ovf", want: false},
		{path: "test.txt", want: false},
		{path: "test.vmdk", want: false},
		{path: "test.vdi", want: false},
		{path: "test.vhdx", want: false},
		{path: "test.vhd", want: false},
		{path: "test.qcow", want: false},
		{path: "test.qcow2", want: false},
		{path: "test.qcow3", want: false},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			f := &testFileInfo{path: test.path}
			got := extractor.FileRequired(f)
			if got != test.want {
				t.Errorf("FileRequired(%q): got %v, want %v", test.path, got, test.want)
			}
		})
	}
}

// TestOVAExtractorOVA tests extraction of disk images from an .ova file.
func TestOVAExtractorOVA(t *testing.T) {
	tests := []struct {
		name         string
		filename     string
		wantLocation string
	}{
		{name: "qcow file", filename: "test-disk.qcow", wantLocation: filepath.Join("test.ova", "test-disk.qcow")},
		{name: "qcow2 file", filename: "test-disk.qcow2", wantLocation: filepath.Join("test.ova", "test-disk.qcow2")},
		{name: "qcow3 file", filename: "test-disk.qcow3", wantLocation: filepath.Join("test.ova", "test-disk.qcow3")},
		{name: "vmdk file", filename: "test-disk.vmdk", wantLocation: filepath.Join("test.ova", "test-disk.vmdk")},
		{name: "vdi file", filename: "test-disk.vdi", wantLocation: filepath.Join("test.ova", "test-disk.vdi")},
		{name: "vhd file", filename: "test-disk.vhd", wantLocation: filepath.Join("test.ova", "test-disk.vhd")},
		{name: "vhdx file", filename: "test-disk.vhdx", wantLocation: filepath.Join("test.ova", "test-disk.vhdx")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create a minimal .ova (tar) with a disk image file.
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			content := "Dummy disk image content"
			if err := tw.WriteHeader(&tar.Header{
				Name:    test.filename,
				Mode:    0644,
				Size:    int64(len(content)),
				ModTime: time.Now(),
			}); err != nil {
				t.Fatalf("Failed to write tar header: %v", err)
			}
			if _, err := tw.Write([]byte(content)); err != nil {
				t.Fatalf("Failed to write file content: %v", err)
			}
			if err := tw.Close(); err != nil {
				t.Fatalf("Failed to close tar writer: %v", err)
			}

			// Create ScanInput with the tar content.
			input := &filesystem.ScanInput{
				Path:   "test.ova",
				Reader: bytes.NewReader(buf.Bytes()),
				Info:   &testFileInfoImpl{path: "test.ova", size: int64(buf.Len())},
			}
			extractor := ova.New()
			inv, err := extractor.Extract(context.Background(), input)
			if err != nil {
				t.Fatalf("Extract failed: %v", err)
			}
			if len(inv.Packages) != 1 {
				t.Fatalf("Expected inventory with 1 package, got %d", len(inv.Packages))
			}
			pkg := inv.Packages[0]
			if pkg.Name != "disk-image" || pkg.PURLType != purl.TypeGeneric || len(pkg.Locations) != 1 || pkg.Locations[0] != test.wantLocation {
				t.Errorf("Expected package with name 'disk-image', PURLType %q, and location %q, got %v", purl.TypeGeneric, test.wantLocation, pkg)
			}
		})
	}
}

// TestOVAExtractorInvalidFile tests that invalid files return empty inventory.
func TestOVAExtractorInvalidFile(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		content string
	}{
		{name: "non-ova extension", path: "test.txt", content: "not an ova file"},
		{name: "ovf file", path: "test.ovf", content: `<?xml version="1.0"?><Envelope></Envelope>`},
		{name: "non-tar ova", path: "test.ova", content: "not a tar file"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := &filesystem.ScanInput{
				Path:   test.path,
				Reader: strings.NewReader(test.content),
				Info:   &testFileInfoImpl{path: test.path, size: int64(len(test.content))},
			}
			extractor := ova.New()
			inv, err := extractor.Extract(context.Background(), input)
			if err != nil {
				t.Fatalf("Extract failed: %v", err)
			}
			if len(inv.Packages) != 0 {
				t.Errorf("Expected empty inventory for %q, got %d packages", test.path, len(inv.Packages))
			}
		})
	}
}
