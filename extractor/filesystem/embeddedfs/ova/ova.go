package ova

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique identifier for the ova extractor.
	Name = "embeddedfs/ova"
)

// Extractor implements the filesystem.Extractor interface for ova.
type Extractor struct{}

// New returns a new ova extractor.
func New() filesystem.Extractor {
	return &Extractor{}
}

// NewDefault returns a New()
func NewDefault() filesystem.Extractor {
	return New()
}

// Name returns the name of the extractor.
func (e *Extractor) Name() string {
	return Name
}

// Version returns the version of the extractor.
func (e *Extractor) Version() int {
	return 0
}

// Requirements returns the requirements for the extractor.
func (e *Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired checks if the file is a .ovf or .ova file.
func (e *Extractor) FileRequired(f filesystem.FileAPI) bool {
	return strings.ToLower(filepath.Ext(f.Path())) == ".ova"
}

// Extract extracts disk image references from .ova files.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	// Initialize empty inventory.
	inv := inventory.Inventory{Packages: []*extractor.Package{}}

	// Check file extension to avoid unnecessary reads.
	if strings.ToLower(filepath.Ext(input.Path)) != ".ova" {
		return inventory.Inventory{}, nil
	}

	// Read the entire file content since Reader is io.Reader.
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}
	readerAt := bytes.NewReader(content)

	// Check if the file is a tar archive using first 512 bytes.
	buf := content
	if len(buf) > 512 {
		buf = buf[:512]
	}
	if !isTar(buf) {
		return inventory.Inventory{}, nil
	}

	// Handle .ova: iterate tar entries and collect disk image paths.
	tr := tar.NewReader(readerAt)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return inventory.Inventory{}, err
		}

		if hdr.Typeflag != tar.TypeReg {
			continue // Skip non-files.
		}

		name := filepath.Clean(hdr.Name)
		if !strings.HasSuffix(strings.ToLower(name), ".vdi") &&
			!strings.HasSuffix(strings.ToLower(name), ".vmdk") &&
			!strings.HasSuffix(strings.ToLower(name), ".vhd") &&
			!strings.HasSuffix(strings.ToLower(name), ".vhdx") &&
			!strings.HasSuffix(strings.ToLower(name), ".qcow") &&
			!strings.HasSuffix(strings.ToLower(name), ".qcow2") &&
			!strings.HasSuffix(strings.ToLower(name), ".qcow3") {
			continue // Only process disk images.
		}

		// Add a placeholder package for the disk image to trigger sub-extraction later.
		inv.Packages = append(inv.Packages, &extractor.Package{
			Name:      "disk-image",
			PURLType:  purl.TypeGeneric,
			Locations: []string{filepath.Join(input.Path, name)},
		})
	}

	return inv, nil
}

// isTar checks if the buffer starts with TAR magic.
func isTar(buf []byte) bool {

	if len(buf) < 262 {
		return false
	}

	return string(buf[257:262]) == "ustar"
}
