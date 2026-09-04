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

package osvutil_test

import (
	"strings"
	"testing"

	"github.com/google/osv-scalibr/enricher/vulnmatch/internal/osvutil"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
)

const rubyGemsPlatformMismatchCDX = `{
    "$schema": "http://cyclonedx.org/schema/bom-1.4.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "components": [
        {
            "bom-ref": "nokogiri-1.19.3-x86_64-linux-gnu",
            "type": "library",
            "name": "nokogiri",
            "version": "1.19.3-x86_64-linux-gnu",
            "purl": "pkg:gem/nokogiri@1.19.3?platform=x86_64-linux-gnu"
        }
    ]
}`

func TestParsePackage_RubyGemsCDXIntegration(t *testing.T) {
	e := cdx.Extractor{}
	input := &filesystem.ScanInput{
		Path:   "testdata/sbom-rubygems-version-mismatch.cdx.json",
		Reader: strings.NewReader(rubyGemsPlatformMismatchCDX),
	}

	inv, err := e.Extract(t.Context(), input)
	if err != nil {
		t.Fatalf("Extract() failed: %v", err)
	}
	if len(inv.Packages) != 1 {
		t.Fatalf("Extract() got %d packages, want 1", len(inv.Packages))
	}

	got := osvutil.ParsePackage(inv.Packages[0])
	if got.Version != "1.19.3" {
		t.Errorf("ParsePackage(cdx-extracted nokogiri).Version = %q, want %q", got.Version, "1.19.3")
	}
}
