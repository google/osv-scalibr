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

//go:build !windows

package regosversion

import (
	"context"
	"fmt"
	"runtime"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// Name of the Windows version extractor
const Name = "windows/regosversion"

// Extractor provides a metadata extractor for the version of Windows.
type Extractor struct{}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// Extract is a no-op for non-Windows platforms.
func (e *Extractor) Extract(ctx context.Context, input *standalone.ScanInput) ([]*extractor.Inventory, error) {
	return nil, fmt.Errorf("only supported on Windows")
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e *Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	log.Warnf("Trying to use regosversion on %s, which is not supported", runtime.GOOS)
	return nil
}

// ToCPEs converts an inventory created by this extractor into CPEs, if supported.
func (e *Extractor) ToCPEs(i *extractor.Inventory) []string {
	log.Warnf("Trying to use regosversion on %s, which is not supported", runtime.GOOS)
	return nil
}

// Ecosystem returns no ecosystem since OSV does not support windows regosversion yet.
func (Extractor) Ecosystem(i *extractor.Inventory) string { return "" }
