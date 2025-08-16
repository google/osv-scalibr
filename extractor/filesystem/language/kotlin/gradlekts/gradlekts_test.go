// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gradlekts_test

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/kotlin/gradlekts"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "build_gradle_kts",
			path:     "build.gradle.kts",
			expected: true,
		},
		{
			name:     "settings_gradle_kts",
			path:     "settings.gradle.kts",
			expected: true,
		},
		{
			name:     "subproject_build_gradle_kts",
			path:     "app/build.gradle.kts",
			expected: true,
		},
		{
			name:     "regular_gradle_file",
			path:     "build.gradle",
			expected: false,
		},
		{
			name:     "kotlin_source_file",
			path:     "src/main/kotlin/Main.kt",
			expected: false,
		},
		{
			name:     "random_file",
			path:     "README.md",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := gradlekts.NewDefault()
			got := e.FileRequired(extracttest.FakeFileAPI{Path: tt.path})
			if got != tt.expected {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		content  string
		expected []*extractor.Package
	}{
		{
			name: "simple_dependencies",
			path: "build.gradle.kts",
			content: `
dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib:1.8.0")
    api("com.google.guava:guava:31.1-jre")
    testImplementation("junit:junit:4.13.2")
}`,
			expected: []*extractor.Package{
				{
					Name:      "org.jetbrains.kotlin:kotlin-stdlib",
					Version:   "1.8.0",
					Locations: []string{"build.gradle.kts"},
				},
				{
					Name:      "com.google.guava:guava",
					Version:   "31.1-jre",
					Locations: []string{"build.gradle.kts"},
				},
				{
					Name:      "junit:junit",
					Version:   "4.13.2",
					Locations: []string{"build.gradle.kts"},
				},
			},
		},
		{
			name: "plugins_block",
			path: "build.gradle.kts",
			content: `
plugins {
    id("org.jetbrains.kotlin.jvm") version "1.8.0"
    id("application")
    id("com.github.johnrengelman.shadow") version "7.1.2"
}`,
			expected: []*extractor.Package{
				{
					Name:      "org.jetbrains.kotlin.jvm",
					Version:   "1.8.0",
					Locations: []string{"build.gradle.kts"},
				},
				{
					Name:      "com.github.johnrengelman.shadow",
					Version:   "7.1.2",
					Locations: []string{"build.gradle.kts"},
				},
			},
		},
		{
			name: "mixed_content",
			path: "build.gradle.kts",
			content: `
plugins {
    id("org.jetbrains.kotlin.jvm") version "1.8.0"
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.6.4")
    // This is a comment
    runtimeOnly("ch.qos.logback:logback-classic:1.2.12")
    
    /* Multi-line comment
       should be ignored */
    compileOnly("org.jetbrains:annotations:23.0.0")
}`,
			expected: []*extractor.Package{
				{
					Name:      "org.jetbrains.kotlin.jvm",
					Version:   "1.8.0",
					Locations: []string{"build.gradle.kts"},
				},
				{
					Name:      "org.jetbrains.kotlinx:kotlinx-coroutines-core",
					Version:   "1.6.4",
					Locations: []string{"build.gradle.kts"},
				},
				{
					Name:      "ch.qos.logback:logback-classic",
					Version:   "1.2.12",
					Locations: []string{"build.gradle.kts"},
				},
				{
					Name:      "org.jetbrains:annotations",
					Version:   "23.0.0",
					Locations: []string{"build.gradle.kts"},
				},
			},
		},
		{
			name: "no_version_specified",
			path: "build.gradle.kts",
			content: `
dependencies {
    implementation("org.springframework:spring-core")
}`,
			expected: []*extractor.Package{
				{
					Name:      "org.springframework:spring-core",
					Version:   "",
					Locations: []string{"build.gradle.kts"},
				},
			},
		},
		{
			name:     "empty_file",
			path:     "build.gradle.kts",
			content:  "",
			expected: []*extractor.Package{},
		},
		{
			name: "comments_only",
			path: "build.gradle.kts",
			content: `
// This is a comment
/* This is also a comment */
`,
			expected: []*extractor.Package{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := gradlekts.NewDefault()
			
			input := &filesystem.ScanInput{
				Path:   tt.path,
				Reader: strings.NewReader(tt.content),
				Root:   "/test",
				Info:   extracttest.FakeFileInfo{},
			}
			
			got, err := e.Extract(context.Background(), input)
			if err != nil {
				t.Fatalf("Extract() error = %v", err)
			}
			
			// Sort packages for consistent comparison
			want := tt.expected
			if diff := cmp.Diff(want, got.Packages, cmpopts.SortSlices(func(a, b *extractor.Package) bool {
				return a.Name < b.Name
			}), cmpopts.IgnoreFields(extractor.Package{}, "PURLType", "Plugins")); diff != "" {
				t.Errorf("Extract() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExtract_InvalidDependencyFormat(t *testing.T) {
	e := gradlekts.NewDefault()
	
	content := `
dependencies {
    implementation("invalid-format")
    implementation("") 
}`
	
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
	
	// Should extract nothing from invalid formats
	if len(got.Packages) != 0 {
		t.Errorf("Extract() should return no packages for invalid formats, got %d", len(got.Packages))
	}
}

func TestExtract_MaxFileSize(t *testing.T) {
	cfg := gradlekts.Config{
		MaxFileSizeBytes: 10, // Very small limit
	}
	e := gradlekts.New(cfg)
	
	// Create a file that's larger than the limit
	largeContent := strings.Repeat("a", 20)
	
	// FileRequired should return false for large files
	api := extracttest.FakeFileAPI{
		Path: "build.gradle.kts",
		FileInfo: extracttest.FakeFileInfo{
			FileName: "build.gradle.kts",
			FileSize: int64(len(largeContent)),
		},
	}
	
	if e.FileRequired(api) {
		t.Error("FileRequired() should return false for files exceeding MaxFileSizeBytes")
	}
}