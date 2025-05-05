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

package npm_test

import (
	"os"
	"path/filepath"
	"testing"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/schema"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/clients/clienttest"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/guidedremediation/internal/lockfile/npm"
	"github.com/google/osv-scalibr/guidedremediation/result"
)

func TestReadV1(t *testing.T) {
	// This lockfile was generated using a private registry with https://verdaccio.org/
	// Mock packages were published to it and installed with npm.
	rw, err := npm.GetReadWriter()
	if err != nil {
		t.Fatalf("error creating ReadWriter: %v", err)
	}
	fsys := scalibrfs.DirFS("./testdata/v1")
	got, err := rw.Read("package-lock.json", fsys)
	if err != nil {
		t.Fatalf("error reading lockfile: %v", err)
	}

	if err := got.Canon(); err != nil {
		t.Fatalf("failed canonicalizing got graph: %v", err)
	}

	want, err := schema.ParseResolve(`
r 1.0.0
	@fake-registry/a@^1.2.3 1.2.3
		$b@^1.0.0
	b: @fake-registry/b@^1.0.1 1.0.1
	Dev KnownAs a-dev|@fake-registry/a@^2.3.4 2.3.4
		# all indirect dependencies become regular because it's impossible to tell type in v1
		@fake-registry/b@^2.0.0 2.0.0
			@fake-registry/c@^1.0.0 1.1.1
				# peerDependencies are not supported in v1
			@fake-registry/d@^2.0.0 2.2.2
	# v1 does not support workspaces
`, resolve.NPM)
	if err != nil {
		t.Fatalf("error parsing want graph: %v", err)
	}

	if err := want.Canon(); err != nil {
		t.Fatalf("failed canonicalizing want graph: %v", err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("npm lockfile mismatch (-want +got):\n%s", diff)
	}
}

func TestReadV2(t *testing.T) {
	// This lockfile was generated using a private registry with https://verdaccio.org/
	// Mock packages were published to it and installed with npm.
	rw, err := npm.GetReadWriter()
	if err != nil {
		t.Fatalf("error creating ReadWriter: %v", err)
	}
	fsys := scalibrfs.DirFS("./testdata/v2")
	got, err := rw.Read("package-lock.json", fsys)
	if err != nil {
		t.Fatalf("error reading lockfile: %v", err)
	}

	if err := got.Canon(); err != nil {
		t.Fatalf("failed canonicalizing got graph: %v", err)
	}

	want, err := schema.ParseResolve(`
r 1.0.0
	@fake-registry/a@^1.2.3 1.2.3
		Opt|$b@^1.0.0
	b: @fake-registry/b@^1.0.1 1.0.1
	Dev KnownAs a-dev|@fake-registry/a@^2.3.4 2.3.4
		@fake-registry/b@^2.0.0 2.0.0
			c: @fake-registry/c@^1.0.0 1.1.1
				Scope peer|$d@^2.0.0
			d: @fake-registry/d@^2.0.0 2.2.2
	# workspace
	w@* 1.0.0
		Dev|@fake-registry/a@^2.3.4 2.3.4
			@fake-registry/b@^2.0.0 2.0.0
				$c@^1.0.0
				$d@^2.0.0
`, resolve.NPM)
	if err != nil {
		t.Fatalf("error parsing want graph: %v", err)
	}

	if err := want.Canon(); err != nil {
		t.Fatalf("failed canonicalizing want graph: %v", err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("npm lockfile mismatch (-want +got):\n%s", diff)
	}
}

func TestTypeOrdering(t *testing.T) {
	// Testing the behavior when a package is included in multiple dependency type fields.
	// Empirically, devDependencies > optionalDependencies > dependencies > peerDependencies

	// This lockfile was manually constructed.
	rw, err := npm.GetReadWriter()
	if err != nil {
		t.Fatalf("error creating ReadWriter: %v", err)
	}
	fsys := scalibrfs.DirFS("./testdata/type_order")
	got, err := rw.Read("package-lock.json", fsys)
	if err != nil {
		t.Fatalf("error reading lockfile: %v", err)
	}

	if err := got.Canon(); err != nil {
		t.Fatalf("failed canonicalizing got graph: %v", err)
	}

	want, err := schema.ParseResolve(`
root 1.0.0
	Dev|a@4.0.0 4.0.0
	Opt|b@3.0.0 3.0.0
	c@2.0.0 2.0.0
	Scope peer|d@1.0.0 1.0.0
`, resolve.NPM)
	if err != nil {
		t.Fatalf("error parsing want graph: %v", err)
	}

	if err := want.Canon(); err != nil {
		t.Fatalf("failed canonicalizing want graph: %v", err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("npm lockfile mismatch (-want +got):\n%s", diff)
	}
}

func TestPeerMeta(t *testing.T) {
	// Testing the behavior with peerDependencies and peerDependenciesMeta.

	// This lockfile was manually constructed.
	rw, err := npm.GetReadWriter()
	if err != nil {
		t.Fatalf("error creating ReadWriter: %v", err)
	}
	fsys := scalibrfs.DirFS("./testdata/peer_meta")
	got, err := rw.Read("package-lock.json", fsys)
	if err != nil {
		t.Fatalf("error reading lockfile: %v", err)
	}

	if err := got.Canon(); err != nil {
		t.Fatalf("failed canonicalizing got graph: %v", err)
	}

	want, err := schema.ParseResolve(`
root 1.0.0
	dep@^1.0.0 1.0.0
		p2: Opt Scope peer|peer2@^2.0.0 2.0.0
		Scope peer KnownAs peer3|peer2@^3.0.0 3.0.0
	$p2@^2.0.0
`, resolve.NPM)
	if err != nil {
		t.Fatalf("error parsing want graph: %v", err)
	}

	if err := want.Canon(); err != nil {
		t.Fatalf("failed canonicalizing want graph: %v", err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("npm lockfile mismatch (-want +got):\n%s", diff)
	}
}

func TestWrite(t *testing.T) {
	// Set up mock npm registry
	srv := clienttest.NewMockHTTPServer(t)
	srv.SetResponseFromFile(t, "/@fake-registry%2fa/1.2.4", "testdata/fake_registry/a-1.2.4.json")
	srv.SetResponseFromFile(t, "/@fake-registry%2fa/2.3.5", "testdata/fake_registry/a-2.3.5.json")

	// Create output directory with npmrc pointing to the registry
	outDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outDir, ".npmrc"), []byte("registry="+srv.URL+"\n"), 0644); err != nil {
		t.Fatalf("error writing npmrc: %v", err)
	}

	// Create patches to write
	patches := []result.Patch{
		{
			PackageUpdates: []result.PackageUpdate{
				{
					Name:        "@fake-registry/a",
					VersionFrom: "1.2.3",
					VersionTo:   "1.2.4",
				},
				{
					Name:        "@fake-registry/a",
					VersionFrom: "2.3.4",
					VersionTo:   "2.3.5",
				},
			},
		},
	}

	want, err := os.ReadFile("testdata/write/want.package-lock.json")
	if err != nil {
		t.Fatalf("error reading want lockfile: %v", err)
	}

	// Write the patched lockfile
	rw, err := npm.GetReadWriter()
	if err != nil {
		t.Fatalf("error creating ReadWriter: %v", err)
	}
	gotPath := filepath.Join(outDir, "package-lock.json")
	if err := rw.Write("write/package-lock.json", scalibrfs.DirFS("testdata"), patches, gotPath); err != nil {
		t.Fatalf("error writing lockfile: %v", err)
	}
	got, err := os.ReadFile(gotPath)
	if err != nil {
		t.Fatalf("error reading got lockfile: %v", err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("npm lockfile mismatch (-want +got):\n%s", diff)
	}
}
