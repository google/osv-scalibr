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

package npm_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/go-cmp/cmp"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest/npm"
	"github.com/google/osv-scalibr/guidedremediation/result"
)

func aliasType(t *testing.T, aliasedName string) dep.Type {
	t.Helper()
	var typ dep.Type
	typ.AddAttr(dep.KnownAs, aliasedName)

	return typ
}

func makeVK(t *testing.T, name, version string, versionType resolve.VersionType) resolve.VersionKey {
	t.Helper()
	return resolve.VersionKey{
		PackageKey: resolve.PackageKey{
			System: resolve.NPM,
			Name:   name,
		},
		Version:     version,
		VersionType: versionType,
	}
}

func makeReqKey(t *testing.T, name, knownAs string) manifest.RequirementKey {
	t.Helper()
	var typ dep.Type
	if knownAs != "" {
		typ.AddAttr(dep.KnownAs, knownAs)
	}

	return npm.MakeRequirementKey(resolve.RequirementVersion{
		VersionKey: resolve.VersionKey{
			PackageKey: resolve.PackageKey{
				Name:   name,
				System: resolve.NPM,
			},
		},
		Type: typ,
	})
}

type testManifest struct {
	FilePath       string
	Root           resolve.Version
	System         resolve.System
	Requirements   []resolve.RequirementVersion
	Groups         map[manifest.RequirementKey][]string
	LocalManifests []testManifest
}

func checkManifest(t *testing.T, name string, got manifest.Manifest, want testManifest) {
	t.Helper()
	if want.FilePath != got.FilePath() {
		t.Errorf("%s.FilePath() = %q, want %q", name, got.FilePath(), want.FilePath)
	}
	if diff := cmp.Diff(want.Root, got.Root()); diff != "" {
		t.Errorf("%s.Root() (-want +got):\n%s", name, diff)
	}
	if want.System != got.System() {
		t.Errorf("%s.System() = %v, want %v", name, got.System(), want.System)
	}
	if diff := cmp.Diff(want.Requirements, got.Requirements()); diff != "" {
		t.Errorf("%s.Requirements() (-want +got):\n%s", name, diff)
	}
	if diff := cmp.Diff(want.Groups, got.Groups()); diff != "" {
		t.Errorf("%s.Groups() (-want +got):\n%s", name, diff)
	}
	gotLocal := got.LocalManifests()
	if len(want.LocalManifests) != len(got.LocalManifests()) {
		t.Errorf("got %d %s.LocalManifests(), want %d", len(gotLocal), name, len(want.LocalManifests))
	}
	n := min(len(gotLocal), len(want.LocalManifests))
	for i := range n {
		checkManifest(t, fmt.Sprintf("%s.LocalManifests[%d]", name, i), gotLocal[i], want.LocalManifests[i])
	}
}

func TestRead(t *testing.T) {
	rw, err := npm.GetReadWriter()
	if err != nil {
		t.Fatalf("error creating ReadWriter: %v", err)
	}
	fsys := scalibrfs.DirFS("./testdata")
	got, err := rw.Read("package.json", fsys)
	if err != nil {
		t.Fatalf("error reading manifest: %v", err)
	}

	want := testManifest{
		FilePath: "package.json",
		Root: resolve.Version{
			VersionKey: makeVK(t, "npm-manifest", "1.0.0", resolve.Concrete),
		},
		System: resolve.NPM,
		Requirements: []resolve.RequirementVersion{
			{
				Type:       aliasType(t, "cliui"), // sorts on aliased name, not real package name
				VersionKey: makeVK(t, "@isaacs/cliui", "^8.0.2", resolve.Requirement),
			},
			{
				// Type: dep.NewType(dep.Dev), devDependencies treated as prod to make resolution work
				VersionKey: makeVK(t, "eslint", "^8.57.0", resolve.Requirement),
			},
			{
				Type:       dep.NewType(dep.Opt),
				VersionKey: makeVK(t, "glob", "^10.3.10", resolve.Requirement),
			},
			{
				VersionKey: makeVK(t, "jquery", "latest", resolve.Requirement),
			},
			{
				VersionKey: makeVK(t, "lodash", "4.17.17", resolve.Requirement),
			},
			{
				VersionKey: makeVK(t, "string-width", "^5.1.2", resolve.Requirement),
			},
			{
				Type:       aliasType(t, "string-width-aliased"),
				VersionKey: makeVK(t, "string-width", "^4.2.3", resolve.Requirement),
			},
		},
		Groups: map[manifest.RequirementKey][]string{
			makeReqKey(t, "eslint", ""): {"dev"},
			makeReqKey(t, "glob", ""):   {"optional"},
		},
	}

	checkManifest(t, "Manifest", got, want)
}

func TestReadWithWorkspaces(t *testing.T) {
	rw, err := npm.GetReadWriter()
	if err != nil {
		t.Fatalf("error creating ReadWriter: %v", err)
	}
	fsys := scalibrfs.DirFS("./testdata/workspaces")
	got, err := rw.Read("package.json", fsys)
	if err != nil {
		t.Fatalf("error reading manifest: %v", err)
	}

	want := testManifest{
		FilePath: "package.json",
		Root: resolve.Version{
			VersionKey: makeVK(t, "npm-workspace-test", "1.0.0", resolve.Concrete),
		},
		System: resolve.NPM,
		Requirements: []resolve.RequirementVersion{
			// root dependencies always before workspace
			{
				Type:       aliasType(t, "jquery-real"),
				VersionKey: makeVK(t, "jquery", "^3.7.1", resolve.Requirement),
			},
			// workspaces in path order
			{
				VersionKey: makeVK(t, "jquery:workspace", "^3.7.1", resolve.Requirement),
			},
			{
				VersionKey: makeVK(t, "@workspace/ugh:workspace", "*", resolve.Requirement),
			},
			{
				VersionKey: makeVK(t, "z-z-z:workspace", "*", resolve.Requirement),
			},
		},
		Groups: map[manifest.RequirementKey][]string{
			makeReqKey(t, "jquery", "jquery-real"): {"dev"},
			// excludes workspace dev dependency
		},
		LocalManifests: []testManifest{
			{
				FilePath: "ws/jquery/package.json",
				Root: resolve.Version{
					VersionKey: makeVK(t, "jquery:workspace", "3.7.1", resolve.Concrete),
				},
				System: resolve.NPM,
				Requirements: []resolve.RequirementVersion{
					{
						VersionKey: makeVK(t, "semver", "^7.6.0", resolve.Requirement),
					},
				},
				Groups: map[manifest.RequirementKey][]string{},
			},
			{
				FilePath: "ws/ugh/package.json",
				Root: resolve.Version{
					VersionKey: makeVK(t, "@workspace/ugh:workspace", "0.0.1", resolve.Concrete),
				},
				System: resolve.NPM,
				Requirements: []resolve.RequirementVersion{
					{
						VersionKey: makeVK(t, "jquery:workspace", "*", resolve.Requirement),
					},
					{
						VersionKey: makeVK(t, "semver", "^6.3.1", resolve.Requirement),
					},
				},
				Groups: map[manifest.RequirementKey][]string{
					makeReqKey(t, "jquery:workspace", ""): {"dev"},
					makeReqKey(t, "semver", ""):           {"dev"},
				},
			},
			{
				FilePath: "z/package.json",
				Root: resolve.Version{
					VersionKey: makeVK(t, "z-z-z:workspace", "1.0.0", resolve.Concrete),
				},
				System: resolve.NPM,
				Requirements: []resolve.RequirementVersion{
					{
						VersionKey: makeVK(t, "@workspace/ugh:workspace", "*", resolve.Requirement),
					},
					{
						VersionKey: makeVK(t, "semver", "^5.7.2", resolve.Requirement),
					},
				},
				Groups: map[manifest.RequirementKey][]string{},
			},
		},
	}

	checkManifest(t, "Manifest", got, want)
}

func TestWrite(t *testing.T) {
	rw, err := npm.GetReadWriter()
	if err != nil {
		t.Fatalf("error creating ReadWriter: %v", err)
	}
	fsys := scalibrfs.DirFS("./testdata")
	manif, err := rw.Read("package.json", fsys)
	if err != nil {
		t.Fatalf("error reading manifest: %v", err)
	}

	patches := []result.Patch{
		{
			PackageUpdates: []result.PackageUpdate{
				{
					Name:        "lodash",
					VersionFrom: "4.17.17",
					VersionTo:   "^4.17.21",
				},
				{
					Name:        "eslint",
					VersionFrom: "^8.57.0",
					VersionTo:   "*",
				},
				{
					Name:        "glob",
					VersionFrom: "^10.3.10",
					VersionTo:   "^1.0.0",
				},
				{
					Name:        "jquery",
					VersionFrom: "latest",
					VersionTo:   "~0.0.1",
				},
			},
		},
		{
			PackageUpdates: []result.PackageUpdate{
				{
					Name:        "@isaacs/cliui",
					VersionFrom: "^8.0.2",
					VersionTo:   "^9.0.0",
					Type:        aliasType(t, "cliui"),
				},
				{
					Name:        "string-width",
					VersionFrom: "^5.1.2",
					VersionTo:   "^7.1.0",
				},
				{
					Name:        "string-width",
					VersionFrom: "^4.2.3",
					VersionTo:   "^6.1.0",
					Type:        aliasType(t, "string-width-aliased"),
				},
			},
		},
	}
	outDir := t.TempDir()
	outFile := filepath.Join(outDir, "package.json")

	if err := rw.Write(manif, fsys, patches, outFile); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read got package.json: %v", err)
	}
	want, err := os.ReadFile(filepath.Join("./testdata", "write_want.package.json"))
	if err != nil {
		t.Fatalf("failed to read want package.json: %v", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("package.json (-want +got):\n%s", diff)
	}
}
