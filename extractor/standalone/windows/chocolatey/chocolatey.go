// Copyright 2025 Google LLC
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

//go:build windows

// Package chocolatey extracts installed Chocolatey packages on Windows.
package chocolatey

import (
	"context"
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "windows/chocolatey"
	
	// Default Chocolatey installation path
	defaultChocolateyPath = `C:\ProgramData\chocolatey\lib`
)

// Config is the configuration for the Extractor.
type Config struct {
	// ChocolateyPath is the path to the Chocolatey lib directory.
	// If empty, uses the default path.
	ChocolateyPath string
}

// DefaultConfig returns the default configuration for the extractor.
func DefaultConfig() Config {
	return Config{
		ChocolateyPath: defaultChocolateyPath,
	}
}

// Extractor extracts installed Chocolatey packages.
type Extractor struct {
	chocolateyPath string
}

// New returns a Chocolatey extractor.
func New(cfg Config) *Extractor {
	path := cfg.ChocolateyPath
	if path == "" {
		path = defaultChocolateyPath
	}
	
	return &Extractor{
		chocolateyPath: path,
	}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() standalone.Extractor { return New(DefaultConfig()) }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 1 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		OS:            plugin.OSWindows,
		DirectFS:      true,
		RunningSystem: true,
	}
}

// ChocolateyPackage represents a Chocolatey package metadata.
type ChocolateyPackage struct {
	XMLName xml.Name `xml:"package"`
	Metadata struct {
		ID          string `xml:"id"`
		Version     string `xml:"version"`
		Title       string `xml:"title"`
		Authors     string `xml:"authors"`
		Description string `xml:"description"`
		ProjectURL  string `xml:"projectUrl"`
		Tags        string `xml:"tags"`
	} `xml:"metadata"`
}

// Extract extracts installed Chocolatey packages.
func (e Extractor) Extract(ctx context.Context, input *standalone.ScanInput) (inventory.Inventory, error) {
	// Check if Chocolatey is installed
	if _, err := os.Stat(e.chocolateyPath); os.IsNotExist(err) {
		log.Debugf("Chocolatey not found at %s", e.chocolateyPath)
		return inventory.Inventory{}, nil
	}
	
	packages := []*extractor.Package{}
	
	// Walk through the Chocolatey lib directory
	err := filepath.WalkDir(e.chocolateyPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Debugf("Error walking %s: %v", path, err)
			return nil // Continue walking
		}
		
		// Look for .nuspec files which contain package metadata
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".nuspec") {
			pkg, err := e.parseNuspecFile(path)
			if err != nil {
				log.Debugf("Error parsing %s: %v", path, err)
				return nil // Continue walking
			}
			
			if pkg != nil {
				packages = append(packages, pkg)
			}
		}
		
		return nil
	})
	
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to walk Chocolatey directory: %w", err)
	}
	
	return inventory.Inventory{Packages: packages}, nil
}

// parseNuspecFile parses a Chocolatey .nuspec file and extracts package information.
func (e Extractor) parseNuspecFile(filePath string) (*extractor.Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}
	
	var pkg ChocolateyPackage
	if err := xml.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	
	// Skip if essential fields are missing
	if pkg.Metadata.ID == "" {
		return nil, fmt.Errorf("package ID is empty")
	}
	
	// Create the package
	extractorPkg := &extractor.Package{
		Name:      pkg.Metadata.ID,
		Version:   pkg.Metadata.Version,
		Locations: []string{filePath},
		PURLType:  purl.TypeChocolatey,
	}
	
	// Add metadata if available
	if pkg.Metadata.Title != "" || pkg.Metadata.Description != "" || pkg.Metadata.Authors != "" {
		metadata := map[string]interface{}{
			"title":       pkg.Metadata.Title,
			"description": pkg.Metadata.Description,
			"authors":     pkg.Metadata.Authors,
			"projectUrl":  pkg.Metadata.ProjectURL,
			"tags":        pkg.Metadata.Tags,
		}
		extractorPkg.Metadata = metadata
	}
	
	return extractorPkg, nil
}