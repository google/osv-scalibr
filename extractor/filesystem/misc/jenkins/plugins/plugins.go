// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package plugins extracts packages from installed Jenkins plugins.
package plugins

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	archivemeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "jenkins/plugins"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will process.
	// Set to 300 MiB to cover large bundled-SDK plugins (e.g. aws-java-sdk ~299 MiB).
	// The extractor only reads the ZIP central directory + MANIFEST.MF (~35 KB) via
	// io.ReaderAt, so the limit guards against pathological non-ZIP content, not
	// memory usage from reading the full file.
	defaultMaxFileSizeBytes = 300 * units.MiB

	// defaultGroupID is the Maven groupId inherited from the Jenkins plugin-pom,
	// used when the manifest does not specify one.
	defaultGroupID = "org.jenkins-ci.plugins"
)

// Extractor extracts Jenkins plugin packages from .jpi and .hpi archive files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Jenkins plugins extractor.
//
// For most use cases, initialize with:
// ```
// e := New(&cpb.PluginConfig{})
// ```
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}
	return &Extractor{maxFileSizeBytes: maxFileSizeBytes}, nil
}

// Name of the extractor.
func (e *Extractor) Name() string { return Name }

// Version of the extractor.
func (e *Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e *Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the file has a .jpi or .hpi extension.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := filepath.ToSlash(api.Path())
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".jpi" && ext != ".hpi" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}
	if !fileinfo.Mode().IsRegular() {
		return false
	}

	if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultOK)
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

// Extract parses a Jenkins plugin archive and emits one inventory package.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	inv, err := e.extract(ctx, input)
	if e.Stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inv, err
}

func (e *Extractor) extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	// Obtain an io.ReaderAt; fall back to reading the whole file into memory
	// (same pattern as java/archive).
	r, ok := input.Reader.(io.ReaderAt)
	var size int64
	if input.Info != nil {
		size = input.Info.Size()
	}
	if !ok {
		log.Debugf("jenkins/plugins: Reader for %s does not implement ReaderAt, reading into memory", input.Path)
		b, err := io.ReadAll(input.Reader)
		if err != nil {
			return inventory.Inventory{}, fmt.Errorf("jenkins/plugins: failed to read %q: %w", input.Path, err)
		}
		r = bytes.NewReader(b)
		size = int64(len(b))
	}

	zipReader, err := zip.NewReader(r, size)
	if err != nil {
		// Invalid archive – soft skip so a single bad file does not fail the scan.
		log.Debugf("jenkins/plugins: %q is not a valid ZIP archive: %v", input.Path, err)
		return inventory.Inventory{}, nil
	}

	attrs, err := readManifest(zipReader)
	if err != nil {
		log.Warnf("jenkins/plugins: failed to read manifest in %q: %v", input.Path, err)
		return inventory.Inventory{}, nil
	}
	if attrs == nil {
		// No manifest found – soft skip.
		return inventory.Inventory{}, nil
	}

	// Jenkins core falls back to Implementation-Version for plugins built before
	// maven-hpi-plugin 1.3 (see hudson.PluginWrapper#getVersionOf).
	pluginVersion := firstNonEmpty(attrs, "Plugin-Version", "Implementation-Version")
	// maven-hpi-plugin appends a build description to snapshot versions,
	// e.g. "1.0-SNAPSHOT (private-...)". Keep only the version itself.
	pluginVersion = strings.Split(pluginVersion, " ")[0]
	if pluginVersion == "" {
		log.Debugf("jenkins/plugins: %q manifest missing Plugin-Version, skipping", input.Path)
		return inventory.Inventory{}, nil
	}

	// Jenkins core falls back to Extension-Name when Short-Name is missing
	// (see hudson.PluginWrapper#computeShortName).
	shortName := strings.ToLower(firstNonEmpty(attrs, "Short-Name", "Extension-Name"))
	if shortName == "" {
		log.Debugf("jenkins/plugins: %q manifest missing Short-Name, skipping", input.Path)
		return inventory.Inventory{}, nil
	}

	// Older plugins may not have Group-Id. Implementation-Vendor-Id is written by
	// the Maven archiver from the project groupId; otherwise use the default group
	// inherited from the Jenkins plugin-pom.
	groupID := firstNonEmpty(attrs, "Group-Id", "Implementation-Vendor-Id")
	if groupID == "" {
		groupID = defaultGroupID
	}
	groupID = strings.ToLower(groupID)

	pkg := &extractor.Package{
		Name:     fmt.Sprintf("%s:%s", groupID, shortName),
		Version:  pluginVersion,
		PURLType: purl.TypeMaven,
		Metadata: &archivemeta.Metadata{
			GroupID:    groupID,
			ArtifactID: shortName,
		},
		Location: extractor.LocationFromPath(input.Path),
	}

	return inventory.Inventory{Packages: []*extractor.Package{pkg}}, nil
}

// readManifest locates META-INF/MANIFEST.MF in the ZIP and returns its parsed
// MIME header, or nil if the file is not present.
func readManifest(zr *zip.Reader) (textproto.MIMEHeader, error) {
	for _, f := range zr.File {
		if !strings.EqualFold(f.Name, "META-INF/MANIFEST.MF") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open MANIFEST.MF: %w", err)
		}
		defer rc.Close()

		b, err := io.ReadAll(rc)
		if err != nil {
			return nil, fmt.Errorf("failed to read MANIFEST.MF: %w", err)
		}

		// textproto.ReadMIMEHeader requires a blank line at the end; Jenkins
		// manifests may omit it, so we tolerate EOF.
		rd := textproto.NewReader(bufio.NewReader(bytes.NewReader(unfoldManifest(b))))
		h, err := rd.ReadMIMEHeader()
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("failed to parse MANIFEST.MF: %w", err)
		}
		return h, nil
	}
	return nil, nil
}

// unfoldManifest joins MANIFEST.MF continuation lines. Manifest lines are wrapped
// at 72 bytes and continued on the next line after a single leading space, which
// must be removed without adding a separator. textproto would join them with a
// space instead, e.g. "io.jenkins.pl ugins".
func unfoldManifest(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte("\r\n "), nil)
	return bytes.ReplaceAll(b, []byte("\n "), nil)
}

// firstNonEmpty returns the value of the first manifest attribute in keys that is
// set, or an empty string if none are.
func firstNonEmpty(attrs textproto.MIMEHeader, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(attrs.Get(k)); v != "" {
			return v
		}
	}
	return ""
}
