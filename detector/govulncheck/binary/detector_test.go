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

package binary_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/detector/govulncheck/binary"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/language/golang/gobinary"
	"github.com/google/osv-scalibr/inventoryindex"
)

const binaryName = "semaphore-demo-go"

func TestScan(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd(): %v", err)
	}
	det := binary.Detector{OfflineVulnDBPath: filepath.Join(wd, "testdata/vulndb")}
	ix := setupInventoryIndex([]string{binaryName})
	findings, err := det.Scan(context.Background(), ".", ix)
	if err != nil {
		t.Fatalf("detector.Scan(%v): %v", ix, err)
	}
	if len(findings) == 0 {
		t.Fatalf("detector.Scan(%v): expected findings, got none: %v", ix, findings)
	}
	got := findings[0]
	wantTitle := "Excessive memory growth in net/http and golang.org/x/net/http2"
	wantDesc := "An attacker can cause excessive memory growth in a Go server accepting " +
		"HTTP/2 requests.\n\nHTTP/2 server connections contain a cache of HTTP header keys " +
		"sent by the client. While the total number of entries in this cache is capped, an " +
		"attacker sending very large keys can cause the server to allocate approximately 64 " +
		"MiB per open connection."
	wantRec := "Remove the binary or upgrade its affected dependencies to non-vulnerable versions"
	wantExtraPrefix := fmt.Sprintf("Vulnerable dependencies for binary %s: ", filepath.Join("testdata", binaryName))
	want := &detector.Finding{
		Adv: &detector.Advisory{
			ID: &detector.AdvisoryID{
				Publisher: "CVE",
				Reference: "CVE-2022-41717",
			},
			Type:           detector.TypeVulnerability,
			Title:          wantTitle,
			Description:    wantDesc,
			Recommendation: wantRec,
			Sev:            &detector.Severity{Severity: detector.SeverityMedium},
		},
		Target: &detector.TargetDetails{Location: []string{filepath.Join("testdata", binaryName)}},
		Extra:  got.Extra,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("detector.Scan(%v): unexpected findings (-want +got):\n%s", ix, diff)
	}
	// We only check the prefix of the extra info as the specific info surfaced might
	// change between govulncheck versions.
	if !strings.HasPrefix(got.Extra, wantExtraPrefix) {
		t.Errorf("detector.Scan(%v): unexpected extra. Want prefix %q, got %q", ix, wantExtraPrefix, got.Extra)
	}
}

func TestScanErrorInGovulncheck(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd(): %v", err)
	}
	det := binary.Detector{OfflineVulnDBPath: filepath.Join(wd, "testdata/vulndb")}
	ix := setupInventoryIndex([]string{"nonexistent", binaryName})
	result, err := det.Scan(context.Background(), ".", ix)
	if err == nil {
		t.Fatalf("detector.Scan(%v): Expected an error, got none", ix)
	}
	if len(result) == 0 {
		t.Fatalf("detector.Scan(%v): Expected scan results, got none", ix)
	}
}

func setupInventoryIndex(names []string) *inventoryindex.InventoryIndex {
	invs := []*extractor.Inventory{}
	for _, n := range names {
		invs = append(invs, &extractor.Inventory{
			Name:      n,
			Version:   "1.2.3",
			Locations: []string{filepath.Join("testdata", n)},
			Extractor: gobinary.Name,
		})
	}
	ix, _ := inventoryindex.New(invs)
	return ix
}
