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

package archive_test

import (
	"io"
	"strings"
	"testing"

	"deps.dev/util/maven"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
)

func TestParsePomXML(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    *maven.Project
	}{
		{
			name: "no_properties",
			content: `
				<project>
					<groupId>com.example</groupId>
					<artifactId>basic</artifactId>
					<version>1.2.3</version>
					<parent>
						<groupId>com.example</groupId>
						<artifactId>parent</artifactId>
						<version>1.2.3</version>
					</parent>
					<dependencies>
						<dependency>
							<groupId>com.example</groupId>
							<artifactId>dep1</artifactId>
							<version>1.2.3</version>
						</dependency>
						<dependency>
							<groupId>com.example</groupId>
							<artifactId>dep2</artifactId>
							<version>4.5.6</version>
						</dependency>
					</dependencies>
				</project>`,
			want: &maven.Project{
				ProjectKey: maven.ProjectKey{
					GroupID:    "com.example",
					ArtifactID: "basic",
					Version:    "1.2.3",
				},
				Parent: maven.Parent{ProjectKey: maven.ProjectKey{
					GroupID:    "com.example",
					ArtifactID: "parent",
					Version:    "1.2.3",
				}},
				Dependencies: []maven.Dependency{{
					GroupID:    "com.example",
					ArtifactID: "dep1",
					Version:    "1.2.3",
					Type:       "jar",
				}, {
					GroupID:    "com.example",
					ArtifactID: "dep2",
					Version:    "4.5.6",
					Type:       "jar",
				}},
			},
		},
		{
			name: "version_with_satisfied_property",
			content: `
				<project>
					<groupId>com.example</groupId>
					<artifactId>basic</artifactId>
					<version>1.2.3</version>
					<properties>
						<dep.version>${other.property}</dep.version>
						<other.property>1.2.3</other.property>
					</properties>
					<dependencies>
						<dependency>
							<groupId>com.example</groupId>
							<artifactId>dep</artifactId>
							<version>${dep.version}</version>
						</dependency>
					</dependencies>
				</project>`,
			want: &maven.Project{
				ProjectKey: maven.ProjectKey{
					GroupID:    "com.example",
					ArtifactID: "basic",
					Version:    "1.2.3",
				},
				Properties: maven.Properties{Properties: []maven.Property{
					{Name: "dep.version", Value: "${other.property}"},
					{Name: "other.property", Value: "1.2.3"},
				}},
				Dependencies: []maven.Dependency{{
					GroupID:    "com.example",
					ArtifactID: "dep",
					Version:    "1.2.3",
					Type:       "jar",
				}},
			},
		},
		{
			name: "version_with_unknown_property",
			content: `
				<project>
					<groupId>com.example</groupId>
					<artifactId>basic</artifactId>
					<version>1.2.3</version>
					<dependencies>
						<dependency>
							<groupId>com.example</groupId>
							<artifactId>dep</artifactId>
							<version>${not.defined}</version>
						</dependency>
					</dependencies>
				</project>`,
			want: &maven.Project{
				ProjectKey: maven.ProjectKey{
					GroupID:    "com.example",
					ArtifactID: "basic",
					Version:    "1.2.3",
				},
				Properties: maven.Properties{Properties: nil},
				Dependencies: []maven.Dependency{{
					GroupID:    "com.example",
					ArtifactID: "dep",
					Version:    "",
					Type:       "jar",
				}},
			},
		},
		{
			name: "other_metadata_with_unknown_property",
			content: `
				<project>
					<groupId>com.example</groupId>
					<artifactId>basic</artifactId>
					<version>1.2.3</version>
					<dependencies>
						<dependency>
							<groupId>com.example</groupId>
							<artifactId>${not.defined}</artifactId>
							<version>1.2.3</version>
						</dependency>
						<dependency>
							<groupId>${not.defined}</groupId>
							<artifactId>dep1</artifactId>
							<version>1.2.3</version>
						</dependency>
						<dependency>
							<groupId>com.example</groupId>
							<artifactId>dep2</artifactId>
							<version>1.2.3</version>
							<scope>${not.defined}</scope>
						</dependency>
						<dependency>
							<groupId>com.example</groupId>
							<artifactId>good</artifactId>
							<version>7.8.9</version>
						</dependency>
					</dependencies>
				</project>`,
			want: &maven.Project{
				ProjectKey: maven.ProjectKey{
					GroupID:    "com.example",
					ArtifactID: "basic",
					Version:    "1.2.3",
				},
				Properties: maven.Properties{Properties: nil},
				Dependencies: []maven.Dependency{{
					GroupID:    "com.example",
					ArtifactID: "good",
					Version:    "7.8.9",
					Type:       "jar",
				}},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := archive.ParsePomXML(&fakePomXMLSource{content: tc.content})
			if err != nil {
				t.Fatalf("parsePomXML(%q) returned error: %v", tc.content, err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("parsePomXML(%q) returned unexpected diff (-want +got):\n%s", tc.content, diff)
			}
		})
	}
}

type fakePomXMLSource struct {
	content string
}

func (f *fakePomXMLSource) Open() (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(f.content)), nil
}
