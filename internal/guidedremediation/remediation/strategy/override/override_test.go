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

package override_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"deps.dev/util/resolve/dep"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/clients/clienttest"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/internal/guidedremediation/manifest/maven"
	"github.com/google/osv-scalibr/internal/guidedremediation/matchertest"
	"github.com/google/osv-scalibr/internal/guidedremediation/remediation"
	"github.com/google/osv-scalibr/internal/guidedremediation/remediation/result"
	"github.com/google/osv-scalibr/internal/guidedremediation/remediation/strategy/override"
	"github.com/google/osv-scalibr/internal/guidedremediation/remediation/upgrade"
	"github.com/google/osv-scalibr/internal/guidedremediation/resolution"
)

func TestComputePatches(t *testing.T) {
	tests := []struct {
		name         string
		universeFile string
		vulnsFile    string
		manifestPath string
		opts         *remediation.Options
		wantFile     string
	}{
		{
			name:         "maven-zeppelin-server",
			universeFile: "testdata/zeppelin-server/universe.yaml",
			vulnsFile:    "testdata/zeppelin-server/vulnerabilities.yaml",
			manifestPath: "zeppelin-server/pom.xml",
			opts:         remediation.DefaultOptions(),
			wantFile:     "testdata/zeppelin-server/patches.json",
		},
		{
			name:         "maven-classifier",
			universeFile: "testdata/maven-classifier/universe.yaml",
			vulnsFile:    "testdata/maven-classifier/vulnerabilities.yaml",
			manifestPath: "maven-classifier/pom.xml",
			opts:         remediation.DefaultOptions(),
			wantFile:     "testdata/maven-classifier/patches.json",
		},
		{
			name:         "maven-management-only",
			universeFile: "testdata/zeppelin-server/universe.yaml",
			vulnsFile:    "testdata/zeppelin-server/vulnerabilities.yaml",
			manifestPath: "zeppelin-server/parent/pom.xml",
			opts: &remediation.Options{
				ResolveOptions: resolution.ResolveOptions{
					MavenManagement: true,
				},
				DevDeps:       true,
				MaxDepth:      -1,
				UpgradeConfig: upgrade.NewConfig(),
			},
			wantFile: "testdata/zeppelin-server/parent/patches.json",
		},
		{
			name:         "workaround-maven-guava-none-to-jre",
			universeFile: "testdata/workaround/universe.yaml",
			vulnsFile:    "testdata/workaround/vulnerabilities.yaml",
			manifestPath: "workaround/guava/none-to-jre/pom.xml",
			opts:         remediation.DefaultOptions(),
			wantFile:     "testdata/workaround/guava/none-to-jre/patches.json",
		},
		{
			name:         "workaround-maven-guava-jre-to-jre",
			universeFile: "testdata/workaround/universe.yaml",
			vulnsFile:    "testdata/workaround/vulnerabilities.yaml",
			manifestPath: "workaround/guava/jre-to-jre/pom.xml",
			opts:         remediation.DefaultOptions(),
			wantFile:     "testdata/workaround/guava/jre-to-jre/patches.json",
		},
		{
			name:         "workaround-maven-guava-android-to-android",
			universeFile: "testdata/workaround/universe.yaml",
			vulnsFile:    "testdata/workaround/vulnerabilities.yaml",
			manifestPath: "workaround/guava/android-to-android/pom.xml",
			opts:         remediation.DefaultOptions(),
			wantFile:     "testdata/workaround/guava/android-to-android/patches.json",
		},
		{
			name:         "workaround-commons",
			universeFile: "testdata/workaround/universe.yaml",
			vulnsFile:    "testdata/workaround/vulnerabilities.yaml",
			manifestPath: "workaround/commons/pom.xml",
			opts:         remediation.DefaultOptions(),
			wantFile:     "testdata/workaround/commons/patches.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantFile, err := os.Open(tt.wantFile)
			if err != nil {
				t.Fatalf("failed opening wantFile: %v", err)
			}
			defer wantFile.Close()
			var want []result.Patch
			if err := json.NewDecoder(wantFile).Decode(&want); err != nil {
				t.Fatalf("failed decoding wantFile: %v", err)
			}

			rw, err := maven.GetReadWriter("")
			if err != nil {
				t.Fatalf("failed getting ReadWriter: %v", err)
			}
			fsys := scalibrfs.DirFS("./testdata")
			m, err := rw.Read(tt.manifestPath, fsys)
			if err != nil {
				t.Fatalf("failed reading manifest: %v", err)
			}

			cl := clienttest.NewMockResolutionClient(t, tt.universeFile)
			vm := matchertest.NewMockVulnerabilityMatcher(t, tt.vulnsFile)
			resolved, err := remediation.ResolveManifest(context.Background(), cl, vm, m, tt.opts)
			if err != nil {
				t.Fatalf("failed resolving manifest: %v", err)
			}
			got, err := override.ComputePatches(context.Background(), cl, vm, resolved, tt.opts)
			if err != nil {
				t.Fatalf("failed computing patches: %v", err)
			}

			// Type is not in exported to json, just treat them all as equal
			typeCmp := func(dep.Type, dep.Type) bool { return true }

			if diff := cmp.Diff(want, got, cmpopts.EquateEmpty(), cmp.Comparer(typeCmp)); diff != "" {
				t.Errorf("ComputePatches: unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}
