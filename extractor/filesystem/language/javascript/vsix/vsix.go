// Package vsix extracts npm packages embedded inside VS Code extension (.vsix) files.
//
// A .vsix file is a ZIP archive. Inside it, the extension's own manifest lives at
// extension/package.json, and any bundled npm dependencies live under
// extension/node_modules/. By reading every package.json found inside a
// node_modules/ directory within the archive we surface the full transitive
// dependency tree of the extension and connect it to the OSV npm vulnerability
// feed.
//
// The .vsix file path is used as the Descriptor in PackageLocation so that
// security tooling can attribute a vulnerable npm package directly back to
// the distributable archive that contains it — critical for artifact-registry
// scanning workflows where extensions are never unpacked on the scanning host.
package vsix

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/location"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	Name = "javascript/vsix"

	defaultMaxFileSizeBytes = 500 * units.MiB

	maxPackageJSONSizeBytes int64 = 10 * units.MiB
)

type Extractor struct {
	Stats stats.Collector
	maxFileSizeBytes int64
}

func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := int64(defaultMaxFileSizeBytes)
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}
	return &Extractor{
		maxFileSizeBytes: maxFileSizeBytes,
	}, nil
}

func (e *Extractor) Name() string { return Name }

func (e *Extractor) Version() int { return 0 }

func (e *Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	if !strings.EqualFold(filepath.Ext(api.Path()), ".vsix") {
		return false
	}

	info, err := api.Stat()
	if err != nil {
		return false
	}

	if e.maxFileSizeBytes > 0 && info.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(api.Path(), info.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(api.Path(), info.Size(), stats.FileRequiredResultOK)
	return true
}

func (e *Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

type packageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Extract reads a .vsix archive from input, walks every package.json entry
// found inside a node_modules/ directory, and returns an Inventory of npm
// packages for each entry that has both a name and a version.
//
// Errors from individual package.json entries (bad JSON, missing fields, I/O)
// are logged and skipped so that a single corrupt entry does not abort the
// entire archive scan. An error is returned only when the archive itself cannot
// be opened or read.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {

	data, err := io.ReadAll(io.LimitReader(input.Reader, e.maxFileSizeBytes+1))
	if err != nil {
		e.reportFileExtracted(input.Path, input.Info, err)
		return inventory.Inventory{}, fmt.Errorf("vsix: reading %q: %w", input.Path, err)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		log.Debugf("vsix: %q is not a valid ZIP archive: %v", input.Path, err)
		e.reportFileExtracted(input.Path, input.Info, nil)
		return inventory.Inventory{}, nil
	}

	var pkgs []*extractor.Package

	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			e.reportFileExtracted(input.Path, input.Info, err)
			return inventory.Inventory{Packages: pkgs}, fmt.Errorf("vsix: %q: %w", input.Path, err)
		}

		if path.Base(f.Name) != "package.json" {
			continue
		}

		if !isInNodeModules(f.Name) {
			log.Debugf("vsix: skipping non-dependency manifest %q in %q", f.Name, input.Path)
			continue
		}

		if f.UncompressedSize64 > uint64(maxPackageJSONSizeBytes) {
			log.Debugf("vsix: skipping oversized package.json %q in %q (%d bytes)",
				f.Name, input.Path, f.UncompressedSize64)
			continue
		}

		pkg, err := extractPackageFromEntry(f, input.Path)
		if err != nil {
			log.Debugf("vsix: error reading %q inside %q: %v", f.Name, input.Path, err)
			continue
		}
		if pkg != nil {
			pkgs = append(pkgs, pkg)
		}
	}

	e.reportFileExtracted(input.Path, input.Info, nil)
	return inventory.Inventory{Packages: pkgs}, nil
}

func isInNodeModules(entryPath string) bool {
	parts := strings.Split(entryPath, "/")
	for _, part := range parts[:len(parts)-1] {
		if part == "node_modules" {
			return true
		}
	}
	return false
}

func (e *Extractor) reportFileExtracted(filePath string, info fs.FileInfo, err error) {
	if e.Stats == nil {
		return
	}
	var fileSizeBytes int64
	if info != nil {
		fileSizeBytes = info.Size()
	}
	e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
		Path:          filePath,
		Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
		FileSizeBytes: fileSizeBytes,
	})
}

func extractPackageFromEntry(f *zip.File, vsixPath string) (*extractor.Package, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("opening zip entry: %w", err)
	}
	defer rc.Close()

	limited := io.LimitReader(rc, maxPackageJSONSizeBytes)

	var p packageJSON
	if err := json.NewDecoder(limited).Decode(&p); err != nil {
		// Malformed JSON — log and skip without propagating the error.
		log.Debugf("vsix: skipping malformed package.json %q in %q: %v", f.Name, vsixPath, err)
		return nil, nil //nolint:nilerr
	}

	p.Name = strings.TrimSpace(p.Name)
	p.Version = strings.TrimSpace(p.Version)
	if p.Name == "" || p.Version == "" {
		log.Debugf("vsix: skipping package.json %q in %q: missing name or version", f.Name, vsixPath)
		return nil, nil
	}

	// The .vsix archive path is the canonical Descriptor — it identifies the
	// distributable artifact that contains the dependency. The path of the
	// package.json entry inside the ZIP is stored in Related so that tooling
	// can reconstruct the full attribution chain:
	//   prettier-vscode-11.0.vsix → extension/node_modules/lodash/package.json
	vsixLoc := location.FromPath(vsixPath)
	entryLoc := location.FromPath(path.Join(vsixPath, f.Name))

	return &extractor.Package{
		Name:     p.Name,
		Version:  p.Version,
		PURLType: purl.TypeNPM,
		Location: extractor.PackageLocation{
			Descriptor: &vsixLoc,
			Related:    []location.Location{entryLoc},
		},
	}, nil
}

var _ filesystem.Extractor = (*Extractor)(nil)
