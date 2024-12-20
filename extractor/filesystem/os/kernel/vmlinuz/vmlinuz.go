// Copyright 2024 Google LLC
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

// Package vmlinuz extracts information about vmlinuz compressed kernel images.
package vmlinuz

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/deitch/magic/pkg/magic"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/kernel/vmlinuz"

	// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSizeBytes = 100 * units.MiB
)

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the kernel vmlinuz extractor.
func DefaultConfig() Config {
	return Config{
		Stats:            nil,
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// Extractor extracts information from kernel vmlinuz files (vmlinuz).
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a kernel vmlinuz extractor.
func New(cfg Config) *Extractor {
	return &Extractor{
		stats:            cfg.Stats,
		maxFileSizeBytes: cfg.MaxFileSizeBytes,
	}
}

// Config returns the configuration of the extractor.
func (e Extractor) Config() Config {
	return Config{
		Stats:            e.stats,
		MaxFileSizeBytes: e.maxFileSizeBytes,
	}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches the vmlinuz file patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()

	if !(filepath.Base(path) == "vmlinuz" || strings.HasPrefix(filepath.Base(path), "vmlinuz-")) {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.stats == nil {
		return
	}
	e.stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts information from vmlinuz files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	inventory, err := e.extractFromInput(ctx, input)

	if e.stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inventory, err
}

func (e Extractor) extractFromInput(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	pkgs := []*extractor.Inventory{}

	m, err := osrelease.GetOSRelease(input.FS)
	if err != nil {
		log.Errorf("osrelease.ParseOsRelease(): %v", err)
	}

	// Return if canceled or exceeding deadline.
	if err := ctx.Err(); err != nil {
		return pkgs, fmt.Errorf("%s halted at %q because of context error: %v", e.Name(), input.Path, err)
	}

	r, err := newReaderAt(input.Reader)
	if err != nil {
		return nil, fmt.Errorf("newReaderAt(%s): %w", input.Path, err)
	}

	magicType, err := magic.GetType(r)
	if err != nil {
		return nil, fmt.Errorf("error determining magic type: %s", err)
	}

	if len(magicType) == 0 || magicType[0] != "Linux kernel" {
		return nil, fmt.Errorf("no match with linux kernel found")
	}

	name := magicType[0]
	architecture, version, extendedVersion, format, videoMode, rwRootFS, swapDevice, rootDevice := parseVmlinuzMetadata(magicType)

	i := &extractor.Inventory{
		Name:    name,
		Version: version,
		Metadata: &Metadata{
			Name:              name,
			Version:           version,
			Architecture:      architecture,
			ExtendedVersion:   extendedVersion,
			Format:            format,
			SwapDevice:        swapDevice,
			RootDevice:        rootDevice,
			VideoMode:         videoMode,
			RwRootFs:          rwRootFS,
			OSID:              m["ID"],
			OSVersionCodename: m["VERSION_CODENAME"],
			OSVersionID:       m["VERSION_ID"],
		},
		Locations: []string{input.Path},
	}

	pkgs = append(pkgs, i)

	return pkgs, nil
}

func newReaderAt(ioReader io.Reader) (io.ReaderAt, error) {
	r, ok := ioReader.(io.ReaderAt)
	if ok {
		return r, nil
	}

	// Fallback: In case ioReader does not implement ReadAt, we use a reader on byte buffer instead, which
	// supports ReadAt.
	buff := bytes.NewBuffer([]byte{})
	_, err := io.Copy(buff, ioReader)
	if err != nil {
		return nil, fmt.Errorf("io.Copy(): %w", err)
	}

	return bytes.NewReader(buff.Bytes()), nil
}

func parseVmlinuzMetadata(magicType []string) (string, string, string, string, string, bool, int32, int32) {
	var architecture, version, extendedVersion, format, videoMode, rootHex, swapHex string
	var rwRootFS bool
	var swapDevice, rootDevice int32

	for _, t := range magicType {
		switch {
		// Architecture
		case strings.HasPrefix(t, "x86 "):
			architecture = "x86"
		case strings.HasPrefix(t, "ARM64 "):
			architecture = "arm64"
		case strings.HasPrefix(t, "ARM "):
			architecture = "arm"

		// Format
		case t == "bzImage":
			format = "bzImage"
		case t == "zImage":
			format = "zImage"

		// Version and extended version
		case strings.HasPrefix(t, "version "):
			extendedVersion = strings.TrimPrefix(t, "version ")
			fields := strings.Fields(extendedVersion)
			if len(fields) > 0 {
				version = fields[0]
			}

		// RW-rootFS
		case strings.Contains(t, "rootFS") && strings.HasPrefix(t, "RW-"):
			rwRootFS = true

		// Swap device
		case strings.HasPrefix(t, "swap_dev "):
			swapHex = strings.TrimPrefix(t, "swap_dev 0X")
			swapConv, err := strconv.ParseInt(swapHex, 16, 32)
			if err != nil {
				log.Errorf("Failed to parse swap device: %v", err)
				continue
			}
			swapDevice = int32(swapConv)

		// Root device
		case strings.HasPrefix(t, "root_dev "):
			rootHex = strings.TrimPrefix(t, "swap_dev 0X")
			rootConv, err := strconv.ParseInt(rootHex, 16, 32)
			if err != nil {
				log.Errorf("Failed to parse swap device: %v", err)
				continue
			}
			rootDevice = int32(rootConv)

		// Video mode
		case strings.Contains(t, "VGA") || strings.Contains(t, "Video"):
			videoMode = t
		}
	}

	return architecture, version, extendedVersion, format, videoMode, rwRootFS, swapDevice, rootDevice
}

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
func (Extractor) Ecosystem(i *extractor.Inventory) string {
	m := i.Metadata.(*Metadata)
	osID := cases.Title(language.English).String(toNamespace(m))
	if m.OSVersionID == "" {
		return osID
	}
	return osID + ":" + m.OSVersionID
}

func toNamespace(m *Metadata) string {
	if m.OSID != "" {
		return m.OSID
	}
	log.Errorf("os-release[ID] not set, fallback to 'linux'")
	return "linux"
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	m := i.Metadata.(*Metadata)
	q := map[string]string{}
	distro := toDistro(m)
	if distro != "" {
		q[purl.Distro] = distro
	}

	return &purl.PackageURL{
		Type:       purl.TypeKernel,
		Name:       m.Name,
		Namespace:  toNamespace(m),
		Version:    i.Version,
		Qualifiers: purl.QualifiersFromMap(q),
	}
}

func toDistro(m *Metadata) string {
	// fallback: e.g. 22.04
	if m.OSVersionID != "" {
		return m.OSVersionID
	}
	log.Errorf("VERSION_ID not set in os-release")
	return ""
}
