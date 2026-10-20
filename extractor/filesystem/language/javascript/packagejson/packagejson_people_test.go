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

package packagejson_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson/metadata"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestExtractPeopleFields(t *testing.T) {
	tests := []struct {
		name         string
		fields       string
		wantAuthor   string
		wantContribs []string
		wantMaints   []string
		wantErr      bool
	}{
		{name: "contributors array", fields: `"contributors":["Jane <jane@example.com>"]`, wantContribs: []string{"Jane"}},
		{name: "contributors object array", fields: `"contributors":[{"name":"Jane","email":"jane@example.com"}]`, wantContribs: []string{"Jane"}},
		{name: "contributors string", fields: `"contributors":"Jane <jane@example.com>"`, wantContribs: []string{"Jane"}},
		{name: "reported URL string", fields: `"contributors":"https://github.com/inikulin/parse5/graphs/contributors"`, wantContribs: []string{"https://github.com/inikulin/parse5/graphs/contributors"}},
		{name: "contributors absent"},
		{name: "contributors empty string", fields: `"contributors":""`},
		{name: "contributors empty array", fields: `"contributors":[]`},
		{name: "contributors null", fields: `"contributors":null`},
		{name: "contributors null array entry", fields: `"contributors":[null]`},
		{name: "contributors mixed array", fields: `"contributors":["Jane",{"name":"John"}]`, wantContribs: []string{"Jane", "John"}},
		{name: "contributors number", fields: `"contributors":42`, wantErr: true},
		{name: "contributors boolean", fields: `"contributors":true`, wantErr: true},
		{name: "contributors object", fields: `"contributors":{"name":"Jane"}`, wantErr: true},
		{name: "maintainers array", fields: `"maintainers":["Jane"]`, wantMaints: []string{"Jane"}},
		{name: "maintainers string", fields: `"maintainers":"Jane"`, wantMaints: []string{"Jane"}},
		{name: "maintainers empty string", fields: `"maintainers":""`},
		{name: "maintainers empty array", fields: `"maintainers":[]`},
		{name: "maintainers null", fields: `"maintainers":null`},
		{name: "maintainers null array entry", fields: `"maintainers":[null]`},
		{name: "maintainers number", fields: `"maintainers":42`, wantErr: true},
		{name: "maintainers boolean", fields: `"maintainers":true`, wantErr: true},
		{name: "maintainers object", fields: `"maintainers":{"name":"Jane"}`, wantErr: true},
		{name: "author string", fields: `"author":"Jane <jane@example.com>"`, wantAuthor: "Jane"},
		{name: "author object", fields: `"author":{"name":"Jane"}`, wantAuthor: "Jane"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := `{"name":"example-package","version":"1.0.0","dependencies":{"dep":"^2.0.0"}`
			if tt.fields != "" {
				input += "," + tt.fields
			}
			input += "}"
			e := packagejson.Extractor{}
			got, err := e.Extract(context.Background(), &filesystem.ScanInput{
				Path: "package.json", Reader: strings.NewReader(input),
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("Extract() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got.Packages) != 1 {
				t.Fatalf("Extract() returned %d packages, want 1", len(got.Packages))
			}
			pkg := got.Packages[0]
			if pkg.Name != "example-package" || pkg.Version != "1.0.0" {
				t.Errorf("package identity = %s@%s", pkg.Name, pkg.Version)
			}
			meta, ok := pkg.Metadata.(*metadata.JavascriptPackageJSONMetadata)
			if !ok {
				t.Fatalf("metadata type = %T", pkg.Metadata)
			}
			if meta.Dependencies["dep"] != "^2.0.0" {
				t.Errorf("dependency = %q", meta.Dependencies["dep"])
			}
			if tt.wantAuthor != "" && (meta.Author == nil || meta.Author.Name != tt.wantAuthor) {
				t.Errorf("author = %+v, want %q", meta.Author, tt.wantAuthor)
			}
			checkPeople := func(field string, got []*metadata.Person, want []string) {
				t.Helper()
				if len(got) != len(want) {
					t.Errorf("%s length = %d, want %d", field, len(got), len(want))
					return
				}
				for i, p := range got {
					if p.Name != want[i] {
						t.Errorf("%s[%d].Name = %q, want %q", field, i, p.Name, want[i])
					}
				}
			}
			checkPeople("contributors", meta.Contributors, tt.wantContribs)
			checkPeople("maintainers", meta.Maintainers, tt.wantMaints)
		})
	}
}

func TestExtractPublishedPackageWithStringContributors(t *testing.T) {
	const path = "testdata/parse5-parser-stream/package.json"
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	e, err := packagejson.New(&cpb.PluginConfig{PluginSpecific: []*cpb.PluginSpecificConfig{
		{Config: &cpb.PluginSpecificConfig_JavascriptPackageJson{
			JavascriptPackageJson: &cpb.JavascriptPackageJsonConfig{IncludeDependencies: true},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.Extract(context.Background(), &filesystem.ScanInput{Path: path, Reader: f})
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}
	if len(got.Packages) != 2 {
		t.Fatalf("Extract() returned %d packages, want 2", len(got.Packages))
	}
	root, dep := got.Packages[0], got.Packages[1]
	if root.Name != "parse5-parser-stream" || root.Version != "7.1.2" || root.PURLType != purl.TypeNPM {
		t.Errorf("root package = %s@%s (%s)", root.Name, root.Version, root.PURLType)
	}
	if dep.Name != "parse5" || dep.Version != "7.0.0" || dep.PURLType != purl.TypeNPM {
		t.Errorf("dependency package = %s@%s (%s)", dep.Name, dep.Version, dep.PURLType)
	}
	meta, ok := root.Metadata.(*metadata.JavascriptPackageJSONMetadata)
	if !ok {
		t.Fatalf("root metadata type = %T", root.Metadata)
	}
	if meta.Author == nil || meta.Author.Name != "Ivan Nikulin" || meta.Author.Email != "ifaaan@gmail.com" {
		t.Errorf("author = %+v", meta.Author)
	}
	if len(meta.Contributors) != 1 || meta.Contributors[0].Name != "https://github.com/inikulin/parse5/graphs/contributors" {
		t.Errorf("contributors = %+v", meta.Contributors)
	}
	if meta.Dependencies["parse5"] != "^7.0.0" {
		t.Errorf("dependency requirement = %q", meta.Dependencies["parse5"])
	}
}

func TestExtractMalformedEssentialMetadata(t *testing.T) {
	for _, tt := range []struct {
		name, input string
	}{
		{name: "name number", input: `{"name":42,"version":"1.0.0"}`},
		{name: "version object", input: `{"name":"example","version":{}}`},
		{name: "dependency version number", input: `{"name":"example","version":"1.0.0","dependencies":{"dep":42}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (packagejson.Extractor{}).Extract(context.Background(), &filesystem.ScanInput{
				Path: "package.json", Reader: strings.NewReader(tt.input),
			})
			if err == nil || len(got.Packages) != 0 {
				t.Errorf("Extract() = %+v, %v; want no packages and a decode error", got, err)
			}
		})
	}
}
