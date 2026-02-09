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
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
)

func TestParseFilename(t *testing.T) {
	tests := []struct {
		desc string
		path string
		want *archive.JarProps
	}{
		{
			desc: "[name]-[version]",
			path: "some/path/yolo-1.2.3.jar",
			want: &archive.JarProps{
				ArtifactID: "yolo",
				Version:    "1.2.3",
			},
		},
		{
			desc: "Group_ID_in_filename",
			path: "some/path/com.google.src.yolo-1.2.3.jar",
			want: &archive.JarProps{
				ArtifactID: "com.google.src.yolo",
				Version:    "1.2.3",
				GroupID:    "com.google.src",
			},
		},
		{
			desc: "Multiple_dashes_in_name",
			path: "some/path/the-yolo-package-1.2.3.jar",
			want: &archive.JarProps{
				ArtifactID: "the-yolo-package",
				Version:    "1.2.3",
			},
		},
		{
			desc: "Multiple_dashes_in_version",
			path: "some/path/yolo-1.2.3-jre.jar",
			want: &archive.JarProps{
				ArtifactID: "yolo",
				Version:    "1.2.3-jre",
			},
		},
		{
			desc: "[name]_[version]",
			path: "some/path/the-yolo-package_1.2.3-jre.jar",
			want: &archive.JarProps{
				ArtifactID: "the-yolo-package",
				Version:    "1.2.3-jre",
			},
		},
		{
			desc: "[name].[version]",
			path: "some/path/the-yolo-package.1.2.3-jre.jar",
			want: &archive.JarProps{
				ArtifactID: "the-yolo-package",
				Version:    "1.2.3-jre",
			},
		},
		{
			desc: "ambiguous_versioning",
			path: "mockito-4-2_3-3.2.12.0-RC2.jar",
			// Incorrect parsing behavior: According to
			// https://mvnrepository.com/artifact/org.scalatestplus/mockito-4-2_3/3.2.12.0-RC2
			// The package mockito-4-2_3 and version is 2.12.0-RC2. To get this right we'd need
			// to somehow know that the initial 4-2_3 is part of the package name.
			want: &archive.JarProps{
				ArtifactID: "mockito",
				Version:    "4-2_3-3.2.12.0-RC2",
			},
		},
		{
			desc: "Version_starts_with_'build'",
			path: "some/path/yolo-build1.2.3.jar",
			want: &archive.JarProps{
				ArtifactID: "yolo",
				Version:    "build1.2.3",
			},
		},
		{
			desc: "'build'_part_of_package_name",
			path: "some/path/yolo-buildasd-1.2.3.jar",
			want: &archive.JarProps{
				ArtifactID: "yolo-buildasd",
				Version:    "1.2.3",
			},
		},
		{
			desc: "Version_starts_with_'r'",
			path: "some/path/yolo-r12.jar",
			want: &archive.JarProps{
				ArtifactID: "yolo",
				Version:    "r12",
			},
		},
		{
			desc: "Version_starts_with_'rc'",
			path: "usr/share/java/jcsp-core-rc4.jar",
			want: &archive.JarProps{
				ArtifactID: "jcsp-core",
				Version:    "rc4",
			},
		},
		{
			desc: "'rc'_part_of_package_name",
			path: "some/path/yolo-rc1asd-1.2.3.jar",
			want: &archive.JarProps{
				ArtifactID: "yolo-rc1asd",
				Version:    "1.2.3",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			if got := archive.ParseFilename(tt.path); *got != *tt.want {
				t.Errorf("ParseFilename(%s): got %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestParseFilenameVersionNotFound(t *testing.T) {
	tests := []struct {
		desc string
		path string
	}{
		{
			desc: "no_version_in_name",
			path: "some/path/yolo.jar",
		},

		{
			desc: "not_a_Java_archive",
			path: "some/path/foo",
		},
		{
			desc: "empty_path",
			path: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			if got := archive.ParseFilename(tt.path); got != nil {
				t.Errorf("ParseFilename(%s): got %v, want nil", tt.path, got)
			}
		})
	}
}
