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

package multiplatform_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/multiplatform"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "kotlin_build_file",
			path:     "build.gradle.kts",
			expected: true,
		},
		{
			name:     "scala_build_file",
			path:     "build.sbt",
			expected: true,
		},
		{
			name:     "clojure_deps_file",
			path:     "deps.edn",
			expected: true,
		},
		{
			name:     "zig_build_file",
			path:     "build.zig",
			expected: true,
		},
		{
			name:     "nim_package_file",
			path:     "package.nimble",
			expected: true,
		},
		{
			name:     "crystal_shard_file",
			path:     "shard.yml",
			expected: true,
		},
		{
			name:     "irrelevant_file",
			path:     "README.md",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := multiplatform.NewDefault()
			got := e.FileRequired(extracttest.FakeFileAPI{Path: tt.path})
			if got != tt.expected {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestExtract_Kotlin(t *testing.T) {
	content := `
plugins {
    id("org.jetbrains.kotlin.jvm") version "1.8.0"
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib:1.8.0")
    testImplementation("junit:junit:4.13.2")
}
`

	e := multiplatform.NewDefault()
	input := &filesystem.ScanInput{
		Path:   "build.gradle.kts",
		Reader: strings.NewReader(content),
		Root:   "/test",
		Info:   extracttest.FakeFileInfo{},
	}

	got, err := e.Extract(context.Background(), input)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	expected := []*extractor.Package{
		{
			Name:      "org.jetbrains.kotlin.jvm",
			Version:   "1.8.0",
			Locations: []string{"build.gradle.kts"},
		},
		{
			Name:      "org.jetbrains.kotlin:kotlin-stdlib",
			Version:   "1.8.0",
			Locations: []string{"build.gradle.kts"},
		},
		{
			Name:      "junit:junit",
			Version:   "4.13.2",
			Locations: []string{"build.gradle.kts"},
		},
	}

	if diff := cmp.Diff(expected, got.Packages, cmpopts.SortSlices(func(a, b *extractor.Package) bool {
		return a.Name < b.Name
	}), cmpopts.IgnoreFields(extractor.Package{}, "PURLType", "Plugins", "Metadata")); diff != "" {
		t.Errorf("Extract() mismatch (-want +got):\n%s", diff)
	}
}

func TestExtract_Scala(t *testing.T) {
	content := `
libraryDependencies ++= Seq(
  "org.scala-lang" % "scala-library" % "2.13.8",
  "org.scalatest" %% "scalatest" % "3.2.12" % Test
)
`

	e := multiplatform.NewDefault()
	input := &filesystem.ScanInput{
		Path:   "build.sbt",
		Reader: strings.NewReader(content),
		Root:   "/test",
		Info:   extracttest.FakeFileInfo{},
	}

	got, err := e.Extract(context.Background(), input)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	// Should find at least one package
	if len(got.Packages) == 0 {
		t.Error("Extract() should find packages in Scala build file")
	}
}

func TestExtract_Clojure(t *testing.T) {
	content := `
{:deps {org.clojure/clojure {:mvn/version "1.11.1"}
        ring/ring-core {:mvn/version "1.9.5"}}}
`

	e := multiplatform.NewDefault()
	input := &filesystem.ScanInput{
		Path:   "deps.edn",
		Reader: strings.NewReader(content),
		Root:   "/test",
		Info:   extracttest.FakeFileInfo{},
	}

	got, err := e.Extract(context.Background(), input)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	// Should find at least one package
	if len(got.Packages) == 0 {
		t.Error("Extract() should find packages in Clojure deps file")
	}
}

func TestExtract_EmptyFile(t *testing.T) {
	e := multiplatform.NewDefault()
	input := &filesystem.ScanInput{
		Path:   "build.gradle.kts",
		Reader: strings.NewReader(""),
		Root:   "/test",
		Info:   extracttest.FakeFileInfo{},
	}

	got, err := e.Extract(context.Background(), input)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	if len(got.Packages) != 0 {
		t.Errorf("Extract() should return no packages for empty file, got %d", len(got.Packages))
	}
}

func TestConfig(t *testing.T) {
	cfg := multiplatform.Config{
		EnabledEcosystems:    []string{"kotlin", "scala"},
		MaxConcurrentParsers: 2,
		EnableCaching:        false,
	}

	e := multiplatform.New(cfg)
	if e == nil {
		t.Error("New() should return a valid extractor")
	}

	if e.Name() != multiplatform.Name {
		t.Errorf("Name() = %q, want %q", e.Name(), multiplatform.Name)
	}

	if e.Version() != 1 {
		t.Errorf("Version() = %d, want 1", e.Version())
	}
}