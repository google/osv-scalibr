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

package linetracker

import (
	"encoding/xml"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestDependency_UnmarshalXML verifies that the custom XML unmarshaler for Dependency
// correctly records all supported coordinate fields (groupId, artifactId, version, type, classifier)
// as well as handling minimal or malformed declarations.
func TestDependency_UnmarshalXML(t *testing.T) {
	tests := []struct {
		name    string
		xmlStr  string
		want    []Dependency
		wantErr bool
	}{
		{
			// Tests unmarshaling a <dependency> element with all supported fields (groupId, artifactId, version, type, classifier).
			name: "complete dependency",
			xmlStr: `<dependencies>
  <dependency>
    <groupId>com.example</groupId>
    <artifactId>my-lib</artifactId>
    <version>1.0.0</version>
    <type>jar</type>
    <classifier>tests</classifier>
  </dependency>
</dependencies>`,
			want: []Dependency{
				{GroupID: "com.example", ArtifactID: "my-lib", Version: "1.0.0", Type: "jar", Classifier: "tests"},
			},
		},
		{
			// Tests unmarshaling a minimal <dependency> element containing only groupId and artifactId.
			name: "minimal dependency",
			xmlStr: `<dependencies>
  <dependency>
    <groupId>com.example</groupId>
    <artifactId>my-lib</artifactId>
  </dependency>
</dependencies>`,
			want: []Dependency{
				{GroupID: "com.example", ArtifactID: "my-lib"},
			},
		},
		{
			// Tests unmarshaling a <dependencies> block containing multiple consecutive <dependency> declarations.
			name: "multiple dependencies",
			xmlStr: `<dependencies>
  <dependency>
    <groupId>com.example</groupId>
    <artifactId>first-lib</artifactId>
    <version>1.0.0</version>
  </dependency>
  <dependency>
    <groupId>com.example</groupId>
    <artifactId>second-lib</artifactId>
    <version>2.0.0</version>
  </dependency>
</dependencies>`,
			want: []Dependency{
				{GroupID: "com.example", ArtifactID: "first-lib", Version: "1.0.0"},
				{GroupID: "com.example", ArtifactID: "second-lib", Version: "2.0.0"},
			},
		},
		{
			// Tests that unmarshaling malformed XML correctly produces an error.
			name: "invalid xml",
			xmlStr: `<dependencies>
  <dependency>
    <groupId>com.example</groupId>`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotWrapper struct {
				Deps []Dependency `xml:"dependency"`
			}
			err := xml.Unmarshal([]byte(tt.xmlStr), &gotWrapper)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalXML() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Ignore Offset as it depends on decoder state
				for i := range gotWrapper.Deps {
					gotWrapper.Deps[i].Offset = 0
				}
				if !reflect.DeepEqual(gotWrapper.Deps, tt.want) {
					t.Errorf("UnmarshalXML() got = %v, want %v", gotWrapper.Deps, tt.want)
				}
			}
		})
	}
}

// TestDependency_matches verifies the coordinate matching logic between a raw XML dependency
// declaration and target package details, ensuring proper handling of exact matches,
// normalized types, variable placeholders, and empty/managed version constraints.
func TestDependency_matches(t *testing.T) {
	tests := []struct {
		name       string
		dep        Dependency
		groupID    string
		artifactID string
		version    string
		depType    string
		classifier string
		want       bool
	}{
		{
			// Tests matching when all dependency coordinates (including type and classifier) match exactly.
			name:       "exact match all fields",
			dep:        Dependency{GroupID: "com.example", ArtifactID: "my-lib", Version: "1.0.0", Type: "jar", Classifier: "tests"},
			groupID:    "com.example",
			artifactID: "my-lib",
			version:    "1.0.0",
			depType:    "jar",
			classifier: "tests",
			want:       true,
		},
		{
			// Tests that an empty dependency type in the raw XML is normalized to "jar" during matching.
			name:       "empty depType normalizes to jar",
			dep:        Dependency{GroupID: "com.example", ArtifactID: "my-lib", Version: "1.0.0", Type: "", Classifier: ""},
			groupID:    "com.example",
			artifactID: "my-lib",
			version:    "1.0.0",
			depType:    "jar",
			classifier: "",
			want:       true,
		},
		{
			// Tests that an empty target dependency type is normalized to "jar" during matching.
			name:       "empty target depType normalizes to jar",
			dep:        Dependency{GroupID: "com.example", ArtifactID: "my-lib", Version: "1.0.0", Type: "jar", Classifier: ""},
			groupID:    "com.example",
			artifactID: "my-lib",
			version:    "1.0.0",
			depType:    "",
			classifier: "",
			want:       true,
		},
		{
			// Tests that a mismatched group ID correctly rejects matching.
			name:       "mismatched groupID",
			dep:        Dependency{GroupID: "com.example", ArtifactID: "my-lib", Version: "1.0.0"},
			groupID:    "org.other",
			artifactID: "my-lib",
			version:    "1.0.0",
			want:       false,
		},
		{
			// Tests that a mismatched artifact ID correctly rejects matching.
			name:       "mismatched artifactID",
			dep:        Dependency{GroupID: "com.example", ArtifactID: "my-lib", Version: "1.0.0"},
			groupID:    "com.example",
			artifactID: "other-lib",
			version:    "1.0.0",
			want:       false,
		},
		{
			// Tests that a hardcoded version mismatch correctly rejects matching.
			name:       "mismatched version",
			dep:        Dependency{GroupID: "com.example", ArtifactID: "my-lib", Version: "1.0.0"},
			groupID:    "com.example",
			artifactID: "my-lib",
			version:    "2.0.0",
			want:       false,
		},
		{
			// Tests that a raw version containing a variable placeholder defers exact matching to Pass 2.
			name:       "interpolated version defers to pass 2",
			dep:        Dependency{GroupID: "com.example", ArtifactID: "my-lib", Version: "${my.version}"},
			groupID:    "com.example",
			artifactID: "my-lib",
			version:    "1.0.0",
			want:       false,
		},
		{
			// Tests that an empty version in the raw XML (e.g., managed dependency) matches any target version.
			name:       "empty version matches any version",
			dep:        Dependency{GroupID: "com.example", ArtifactID: "my-lib", Version: ""},
			groupID:    "com.example",
			artifactID: "my-lib",
			version:    "1.0.0",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.dep.matches(tt.groupID, tt.artifactID, tt.version, tt.depType, tt.classifier); got != tt.want {
				t.Errorf("matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNormalizeType verifies that Maven dependency types are correctly normalized,
// specifically ensuring that empty type declarations default to "jar".
func TestNormalizeType(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			// Tests that an empty string normalizes to "jar".
			name: "empty string", input: "", want: "jar",
		},
		{
			// Tests that "jar" remains "jar".
			name: "jar", input: "jar", want: "jar",
		},
		{
			// Tests that "pom" remains "pom".
			name: "pom", input: "pom", want: "pom",
		},
		{
			// Tests that "war" remains "war".
			name: "war", input: "war", want: "war",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeType(tt.input); got != tt.want {
				t.Errorf("normalizeType() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestFindLineNumber checks that we set the expected line number for different scenarios that
// require different matching strategies, i.e. exact match, interpolation match,.
func TestFindLineNumber(t *testing.T) {
	tests := []struct {
		name string
		args FindLineNumberArgs
		want int
	}{
		{
			// Tests that an exact match skips a prior identical dependency if its index is already claimed.
			name: "exact match already claimed",
			args: FindLineNumberArgs{
				GroupID:    "com.example",
				ArtifactID: "my-lib",
				DepType:    "jar",
				RawDeps: []*Dependency{
					{GroupID: "com.example", ArtifactID: "my-lib", Type: "jar", Line: 10},
					{GroupID: "com.example", ArtifactID: "my-lib", Type: "jar", Line: 20},
				},
				UsedRawDeps: map[int]bool{0: true},
			},
			want: 20,
		},
		{
			// Tests that an interpolation match skips a prior identical candidate if its index is already claimed.
			name: "wildcard match already claimed",
			args: FindLineNumberArgs{
				GroupID:    "com.example",
				ArtifactID: "other-lib",
				DepType:    "jar",
				RawDeps: []*Dependency{
					{GroupID: "com.example", ArtifactID: "${wildcard}", Type: "jar", Line: 10},
					{GroupID: "com.example", ArtifactID: "${wildcard}", Type: "jar", Line: 20},
				},
				UsedRawDeps: map[int]bool{0: true},
			},
			want: 20,
		},
		{
			// Tests correctly matching the second declaration (1.1.1) when two versions exist for the same coordinates.
			name: "multi version match second declaration",
			args: FindLineNumberArgs{
				GroupID:    "com.example",
				ArtifactID: "my-lib",
				Version:    "1.1.1",
				DepType:    "jar",
				RawDeps: []*Dependency{
					{GroupID: "com.example", ArtifactID: "my-lib", Version: "1.0.0", Type: "jar", Line: 10},
					{GroupID: "com.example", ArtifactID: "my-lib", Version: "1.1.1", Type: "jar", Line: 20},
				},
				UsedRawDeps: make(map[int]bool),
			},
			want: 20,
		},
		{
			// Tests correctly matching the first declaration (1.0.0) when two versions exist for the same coordinates.
			name: "multi version match first declaration",
			args: FindLineNumberArgs{
				GroupID:    "com.example",
				ArtifactID: "my-lib",
				Version:    "1.0.0",
				DepType:    "jar",
				RawDeps: []*Dependency{
					{GroupID: "com.example", ArtifactID: "my-lib", Version: "1.0.0", Type: "jar", Line: 10},
					{GroupID: "com.example", ArtifactID: "my-lib", Version: "1.1.1", Type: "jar", Line: 20},
				},
				UsedRawDeps: make(map[int]bool),
			},
			want: 10,
		},
		{
			// Tests falling back to the <parent> declaration line number when no raw dependency matches.
			name: "fallback to parent line",
			args: FindLineNumberArgs{
				GroupID:     "com.example",
				ArtifactID:  "inherited-lib",
				RawDeps:     []*Dependency{},
				UsedRawDeps: make(map[int]bool),
				ParentLine:  5,
			},
			want: 5,
		},
		{
			// Tests that a raw dependency with a mismatched placeholder version is not falsely matched as an exact match.
			name: "mismatched placeholder version not matched",
			args: FindLineNumberArgs{
				GroupID:    "com.example",
				ArtifactID: "my-lib",
				Version:    "2.0.0",
				DepType:    "jar",
				RawDeps: []*Dependency{
					{GroupID: "com.example", ArtifactID: "my-lib", Version: "1.${patch}", Type: "jar", Line: 10},
				},
				UsedRawDeps: make(map[int]bool),
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FindLineNumber(tt.args); got != tt.want {
				t.Errorf("FindLineNumber() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRawDependencyLinesList verifies the extraction of raw dependency declarations
// across both active <dependencies> blocks and <profiles>, ensuring that line numbers
// are accurately calculated based on XML stream byte offsets.
func TestRawDependencyLinesList(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []int // line numbers
	}{
		{
			// Tests extracting line numbers and offsets for dependencies declared in both <dependencies> and <profiles>.
			name: "dependencies and profiles",
			content: `<project>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>a</artifactId>
    </dependency>
  </dependencies>
  <profiles>
    <profile>
      <dependencies>
        <dependency>
          <groupId>com.example</groupId>
          <artifactId>b</artifactId>
        </dependency>
      </dependencies>
    </profile>
  </profiles>
</project>`,
			want: []int{3, 11},
		},
		{
			// Tests that malformed XML returns nil without panicking.
			name:    "invalid xml",
			content: `<project><dependencies><dependency><groupId>com.example`,
			want:    nil,
		},
		{
			// Tests that an empty project returns nil.
			name:    "no dependencies",
			content: `<project></project>`,
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RawDependencyLinesList([]byte(tt.content))
			var gotLines []int
			for _, d := range got {
				gotLines = append(gotLines, d.Line)
			}
			if !cmp.Equal(gotLines, tt.want) {
				t.Errorf("RawDependencyLinesList() lines = %v, want %v", gotLines, tt.want)
			}
		})
	}
}

// TestParentLine verifies the XML scanning logic used to locate the starting line number
// of a <parent> POM declaration, testing both valid positioning and fallback defaults.
func TestParentLine(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{
			// Tests locating the starting line number of a <parent> declaration.
			name: "parent on line 2",
			content: `<project>
  <parent>
    <groupId>org.parent</groupId>
  </parent>
</project>`,
			want: 2,
		},
		{
			// Tests that a project without a <parent> tag returns 0.
			name:    "no parent",
			content: `<project></project>`,
			want:    0,
		},
		{
			// Tests that malformed XML returns 0 without panicking.
			name:    "invalid xml",
			content: `<project><par`,
			want:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParentLine([]byte(tt.content)); got != tt.want {
				t.Errorf("ParentLine() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMatchesPlaceholder verifies the variable placeholder matching mechanism, validating
// that resolved coordinate values properly fit within hardcoded XML prefix and suffix boundaries.
func TestMatchesPlaceholder(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		resolved string
		want     bool
	}{
		{
			// Tests matching identical strings.
			name: "exact match", raw: "org.apache", resolved: "org.apache", want: true,
		},
		{
			// Tests matching a variable placeholder located in the middle of the string.
			name: "variable match middle", raw: "org.${group}.common", resolved: "org.apache.common", want: true,
		},
		{
			// Tests matching a variable placeholder located at the end of the string.
			name: "variable match end", raw: "org.apache.${artifact}", resolved: "org.apache.commons", want: true,
		},
		{
			// Tests matching a variable placeholder located at the start of the string.
			name: "variable match start", raw: "${group}.apache.commons", resolved: "org.apache.commons", want: true,
		},
		{
			// Tests rejecting a match when the prefix before the placeholder differs.
			name: "mismatched prefix", raw: "com.${group}.common", resolved: "org.apache.common", want: false,
		},
		{
			// Tests rejecting a match when the suffix after the placeholder differs.
			name: "mismatched suffix", raw: "org.${group}.lib", resolved: "org.apache.common", want: false,
		},
		{
			// Tests rejecting malformed variable syntax missing a closing brace.
			name: "missing closing brace", raw: "org.${group.common", resolved: "org.apache.common", want: false,
		},
		{
			// Tests rejecting malformed variable syntax missing an opening brace.
			name: "missing opening brace", raw: "org.group}.common", resolved: "org.apache.common", want: false,
		},
		{
			// Tests rejecting a match when the resolved string is shorter than the surrounding prefix/suffix.
			name: "resolved too short", raw: "org.apache.commons.${ext}", resolved: "org", want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesPlaceholder(tt.raw, tt.resolved); got != tt.want {
				t.Errorf("matchesPlaceholder() = %v, want %v", got, tt.want)
			}
		})
	}
}
