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

// Package macos extracts packages from Info.plist files of OS X devices.
package macos

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"regexp"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/macos"

	// defaultMaxFileSizeBytes is set to 0 since the xml file is per package and is usually small.
	defaultMaxFileSizeBytes = 0
)

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the MacOS App extractor.
func DefaultConfig() Config {
	return Config{
		Stats:            nil,
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// Extractor extracts MacOS Apps from /Applications Directory.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a MacOS App extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
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

// Should be Info.plist file inside the Applications directory either globally.
var filePathRegex = regexp.MustCompile(`Applications/.*/Contents/.*Info.plist$`)

// FileRequired returns true if the specified file matches the Info.plist file pattern.
func (e Extractor) FileRequired(path string, fileinfo fs.FileInfo) bool {
	if match := filePathRegex.FindString(path); match == "" {
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

// Extract extracts packages from Info.plist files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	i, err := e.extractFromInput(input)
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
	if err != nil {
		return nil, fmt.Errorf("Mac OS Application.extract(%s): %w", input.Path, err)
	}
	if i == nil {
		return []*extractor.Inventory{}, nil
	}
	return []*extractor.Inventory{i}, nil
}

func (e Extractor) extractFromInput(input *filesystem.ScanInput) (*extractor.Inventory, error) {
	// Initialize the decoder
	decoder := xml.NewDecoder(input.Reader)

	var (
		currentKey                                                                                                                 string
		displayName, executable, identifier, bundleName, packageType, shortVersion, signature, bundleVersion, productID, updateURL string
		validFile                                                                                                                  bool
	)

	// Traverse the XML elements
	for {
		// Use a background context if no context is provided
		ctx := context.Background()
		// Check for context cancellation before each token read
		select {
		case <-ctx.Done():
			return nil, ctx.Err() // Return the context error
		default: // Proceed if context is not canceled
		}

		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading XML token: %w", err) // Wrap the error with more context
		}

		// Switch based on the XML token type
		switch t := tok.(type) {
		case xml.StartElement:
			// Check for <key> and <string> elements
			if t.Name.Local == "key" {
				var keyContent string
				err = decoder.DecodeElement(&keyContent, &t)
				if err != nil {
					return nil, fmt.Errorf("Error Decoding Key token: %w", err) // Wrap the error with more context
				}
				currentKey = keyContent
				validFile = true

			}
			if t.Name.Local == "string" {
				var valueContent string
				decoder.DecodeElement(&valueContent, &t)

				// Check for the keys we care about
				if currentKey == "CFBundleDisplayName" {
					displayName = valueContent
				} else if currentKey == "CFBundleExecutable" {
					executable = valueContent
				} else if currentKey == "CFBundleIdentifier" {
					identifier = valueContent
				} else if currentKey == "CFBundleName" {
					bundleName = valueContent
				} else if currentKey == "CFBundlePackageType" {
					packageType = valueContent
				} else if currentKey == "CFBundleShortVersionString" {
					shortVersion = valueContent
				} else if currentKey == "CFBundleSignature" {
					signature = valueContent
				} else if currentKey == "CFBundleVersion" {
					bundleVersion = valueContent
				} else if currentKey == "KSProductID" {
					productID = valueContent
				} else if currentKey == "KSUpdateURL" {
					updateURL = valueContent
				}
			}
		}
	}
	if !validFile {
		return nil, fmt.Errorf("Invalid Info.plist file ")
	}
	i := &extractor.Inventory{
		Name:    displayName,
		Version: shortVersion,
		Metadata: &Metadata{
			PackageName:       displayName,
			PackageID:         identifier,
			PackageVersion:    shortVersion,
			BundleExecutable:  executable,
			BundleName:        bundleName,
			BundlePackageType: packageType,
			BundleSignature:   signature,
			BundleVersion:     bundleVersion,
			KSProductID:       productID,
			KSUpdateURL:       updateURL,
		},
		Locations: []string{input.Path},
	}

	return i, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {

	return &purl.PackageURL{
		Type:    purl.TypeMacApps,
		Name:    i.Name,
		Version: i.Version,
	}
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Extractor) ToCPEs(i *extractor.Inventory) []string { return []string{} }

// Ecosystem returns no Ecosystem since the ecosystem is not known by OSV yet.
func (e Extractor) Ecosystem(i *extractor.Inventory) string { return "" }
