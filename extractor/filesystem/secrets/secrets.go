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

// Package secrets contains a Scalibr filesystem Extractor that wraps the Veles
// secret scanning library to find secrets (i.e. credentials) in files on the
// filesystem.
package secrets

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/anthropicapikey"
	"github.com/google/osv-scalibr/veles/secrets/azuretoken"
	"github.com/google/osv-scalibr/veles/secrets/digitaloceanapikey"
	"github.com/google/osv-scalibr/veles/secrets/dockerhubpat"
	"github.com/google/osv-scalibr/veles/secrets/gcpsak"
	grokxaiapikey "github.com/google/osv-scalibr/veles/secrets/grokxaiapikey"
	"github.com/google/osv-scalibr/veles/secrets/openai"
	perplexityapikey "github.com/google/osv-scalibr/veles/secrets/perplexityapikey"
	postmanapikey "github.com/google/osv-scalibr/veles/secrets/postmanapikey"
	"github.com/google/osv-scalibr/veles/secrets/privatekey"
	"github.com/google/osv-scalibr/veles/secrets/tinkkeyset"
)

const (
	// Name is the unique name of this extractor.
	Name = "secrets/veles"

	version = 1
)

var (
	fileExtensions = map[string]bool{
		".cfg":       true,
		".env":       true,
		".html":      true,
		".ipynb":     true,
		".json":      true,
		".log":       true,
		".md":        true,
		".py":        true,
		".textproto": true,
		".toml":      true,
		".txt":       true,
		".xml":       true,
		".yaml":      true,
		".pem":       true,
		".crt":       true,
		".key":       true,
		".der":       true,
		".cer":       true,
	}

	defaultEngine *veles.DetectionEngine
)

func init() { //nolint:gochecknoinits
	var err error
	defaultEngine, err = veles.NewDetectionEngine([]veles.Detector{
		anthropicapikey.NewDetector(),
		gcpsak.NewDetector(),
		dockerhubpat.NewDetector(),
		digitaloceanapikey.NewDetector(),
		perplexityapikey.NewDetector(),
		grokxaiapikey.NewAPIKeyDetector(),
		grokxaiapikey.NewManagementKeyDetector(),
		privatekey.NewDetector(),
		azuretoken.NewDetector(),
		tinkkeyset.NewDetector(),
		openai.NewDetector(),
		postmanapikey.NewAPIKeyDetector(),
		postmanapikey.NewCollectionTokenDetector(),
	})
	if err != nil {
		panic(fmt.Sprintf("Unable to initialize default Veles engine: %v", err))
	}
}

// Extractor extracts secrets from the filesystem using the Veles secret
// scanning library.
// Other than most extractors, it adds Secrets to the Inventory, not Packages.
type Extractor struct {
	e *veles.DetectionEngine
}

// New creates a new Extractor using the default Veles detectors.
func New() filesystem.Extractor {
	return &Extractor{e: defaultEngine}
}

// NewWithEngine creates a new Extractor that uses the specified
// DetectionEngine.
func NewWithEngine(e *veles.DetectionEngine) filesystem.Extractor {
	return &Extractor{e: e}
}

// Name of the Extractor.
func (e Extractor) Name() string {
	return Name
}

// Version of the Extractor.
func (e Extractor) Version() int {
	return version
}

// Requirements of the Extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true, if the file should be checked for secrets.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	ext := strings.ToLower(filepath.Ext(api.Path()))
	return fileExtensions[ext]
}

// Extract extracts secrets from scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	secrets, err := e.e.Detect(ctx, input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("unable to scan for secrets: %w", err)
	}
	i := inventory.Inventory{}
	for _, s := range secrets {
		i.Secrets = append(i.Secrets, &inventory.Secret{
			Secret:   s,
			Location: input.Path,
		})
	}
	return i, nil
}
