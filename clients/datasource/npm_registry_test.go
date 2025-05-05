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

package datasource_test

import (
	"cmp"
	"context"
	"path/filepath"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/clients/clienttest"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/tidwall/gjson"
)

func TestNpmRegistryClient(t *testing.T) {
	//nolint:gosec  // "Potential hardcoded credentials" :)
	const (
		auth      = "Y29vbDphdXRoCg=="
		authToken = "bmljZS10b2tlbgo="
	)

	srv1 := clienttest.NewMockHTTPServer(t)
	srv1.SetAuthorization(t, "Basic "+auth)
	srv1.SetResponseFromFile(t, "/fake-package", "./testdata/npm_registry/fake-package.json")
	srv1.SetResponseFromFile(t, "/fake-package/2.2.2", "./testdata/npm_registry/fake-package-2.2.2.json")

	srv2 := clienttest.NewMockHTTPServer(t)
	srv2.SetAuthorization(t, "Bearer "+authToken)
	srv2.SetResponseFromFile(t, "/@fake-registry%2fa", "./testdata/npm_registry/fake-registry-a.json")

	npmrcFile := createTempNpmrc(t, ".npmrc")
	writeToNpmrc(t, npmrcFile,
		"registry="+srv1.URL,
		"//"+strings.TrimPrefix(srv1.URL, "http://")+"/:_auth="+auth,
		"@fake-registry:registry="+srv2.URL,
		"//"+strings.TrimPrefix(srv2.URL, "http://")+"/:_authToken="+authToken,
	)

	cl, err := datasource.NewNPMRegistryAPIClient(filepath.Dir(npmrcFile))
	if err != nil {
		t.Fatalf("failed creating npm api client: %v", err)
	}
	{
		const pkg = "fake-package"
		want := datasource.NPMRegistryVersions{
			Versions: []string{"1.0.0", "2.2.2"},
			Tags: map[string]string{
				"latest":   "1.0.0",
				"version1": "1.0.0",
				"version2": "2.2.2",
			},
		}
		got, err := cl.Versions(context.Background(), pkg)
		if err != nil {
			t.Fatalf("failed getting versions: %v", err)
		}
		if diff := gocmp.Diff(want, got, cmpopts.SortSlices(cmp.Less[string])); diff != "" {
			t.Errorf("Versions(\"%s\") (-want +got)\n%s", pkg, diff)
		}
	}
	{
		const pkg = "@fake-registry/a"
		want := datasource.NPMRegistryVersions{
			Versions: []string{"1.2.3", "2.3.4"},
			Tags:     map[string]string{"latest": "2.3.4"},
		}
		got, err := cl.Versions(context.Background(), pkg)
		if err != nil {
			t.Fatalf("failed getting versions: %v", err)
		}
		if diff := gocmp.Diff(want, got, cmpopts.SortSlices(cmp.Less[string])); diff != "" {
			t.Errorf("Versions(\"%s\") (-want +got)\n%s", pkg, diff)
		}
	}

	{
		const pkg = "fake-package"
		const ver = "2.2.2"
		want := datasource.NPMRegistryDependencies{
			Dependencies: map[string]string{
				"a": "^3.0.1",
				"b": "^2.0.1",
				"e": "^0.2.33",
				"f": "npm:g@^2.0.1",
			},
			DevDependencies: map[string]string{
				"c": "^1.1.1",
				"d": "^1.0.2",
			},
			PeerDependencies: map[string]string{
				"h": "^1.0.0",
			},
			OptionalDependencies: map[string]string{
				"e": "^0.2.33",
				"f": "npm:g@^2.0.1",
			},
			BundleDependencies: []string{
				"a",
			},
		}
		got, err := cl.Dependencies(context.Background(), pkg, ver)
		if err != nil {
			t.Fatalf("failed getting dependencies: %v", err)
		}
		if diff := gocmp.Diff(want, got, cmpopts.SortSlices(cmp.Less[string])); diff != "" {
			t.Errorf("Dependencies(\"%s\", \"%s\") (-want +got)\n%s", pkg, ver, diff)
		}
	}
	{
		const pkg = "fake-package"
		const ver = "2.2.2"
		want := gjson.Parse(`{
			"name": "fake-package",
			"version": "2.2.2",
			"main": "index.js",
			"scripts": {
				"test": "echo \"Error: no test specified\" && exit 1"
			},
			"author": "",
			"license": "ISC",
			"dependencies": {
				"a": "^3.0.1",
				"b": "^2.0.1",
				"e": "^0.2.33",
				"f": "npm:g@^2.0.1"
			},
			"devDependencies": {
				"c": "^1.1.1",
				"d": "^1.0.2"
			},
			"optionalDependencies": {
				"e": "^0.2.33",
				"f": "npm:g@^2.0.1"
			},
			"peerDependencies": {
				"h": "^1.0.0"
			},
			"bundleDependencies": [
				"a"
			],
			"_id": "fake-package@2.2.2",
			"_nodeVersion": "20.9.0",
			"_npmVersion": "10.1.0",
			"dist": {
				"integrity": "sha512-NWvNE9fxykrzSQVr1CSKchzkQr5qwplvgn3O/0JL46qM6BhoGlKRjLiaZYdo1byXJWLGthghOgGpUZiEL04HQQ==",
				"shasum": "8dc47515da4e67bb794a4c9c7f4750bb4d67c7fc",
				"tarball": "http://localhost:4873/fake-package/-/fake-package-2.2.2.tgz"
			},
			"contributors": []
		}`)
		got, err := cl.FullJSON(context.Background(), pkg, ver)
		if err != nil {
			t.Fatalf("failed getting full json: %v", err)
		}
		wantMap := want.Value().(map[string]any)
		gotMap := got.Value().(map[string]any)
		if diff := gocmp.Diff(wantMap, gotMap, cmpopts.SortSlices(cmp.Less[string])); diff != "" {
			t.Errorf("FullJSON(\"%s\", \"%s\") (-want +got)\n%s", pkg, ver, diff)
		}
	}
}
