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

// Package python provides the lockfile parsing and writing for requirements.txt.
package python

import (
	"errors"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/guidedremediation/internal/lockfile"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
)

type readWriter struct{}

// GetReadWriter returns a dummy ReadWriter for requirements.txt as lockfiles.
func GetReadWriter() (lockfile.ReadWriter, error) { return readWriter{}, nil }

// System returns the ecosystem of this ReadWriter.
func (r readWriter) System() resolve.System { return resolve.PyPI }

// SupportedStrategies returns the remediation strategies supported for this lockfile.
// We currently don't support any strategies for requirements.txt.
func (r readWriter) SupportedStrategies() []strategy.Strategy {
	return []strategy.Strategy{}
}

// Read is not supported as intended for requirements.txt.
// It's tricky to read the dependency graph from the requirements.txt, so we rely on pip-compile
// to re-generate requirements.txt if there is manifest (e.g. requirements.in).
func (r readWriter) Read(path string, fsys fs.FS) (*resolve.Graph, error) {
	return nil, errors.New("not supported")
}

// Write is not supported as intended for requirements.txt.
func (r readWriter) Write(path string, fsys fs.FS, patches []result.Patch, outputPath string) error {
	return errors.New("not supported")
}
