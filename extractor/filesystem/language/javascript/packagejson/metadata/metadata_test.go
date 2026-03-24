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

package metadata_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson/metadata"
	"google.golang.org/protobuf/testing/protocmp"

	pb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

func TestUnmarshalJSON_Person(t *testing.T) {
	testCases := []struct {
		desc    string
		input   string
		want    *metadata.Person
		wantErr error
	}{
		{
			desc:  "empty person",
			input: `""`,
			want:  &metadata.Person{},
		},
		{
			desc:  "full person string",
			input: `"Developer <dev@corp.com> (http://dev.blog.com)"`,
			want: &metadata.Person{
				Name:  "Developer",
				Email: "dev@corp.com",
				URL:   "http://dev.blog.com",
			},
		},
		{
			desc:  "person string no name",
			input: `"<dev@corp.com> (http://dev.blog.com)"`,
			want:  &metadata.Person{},
		},
		{
			desc:  "person string no email",
			input: `"Developer (http://dev.blog.com)"`,
			want: &metadata.Person{
				Name: "Developer",
				URL:  "http://dev.blog.com",
			},
		},
		{
			desc:  "person string no url",
			input: `"Developer <dev@corp.com>"`,
			want: &metadata.Person{
				Name:  "Developer",
				Email: "dev@corp.com",
			},
		},
		{
			desc:  "empty person object",
			input: `{}`,
			want:  &metadata.Person{},
		},
		{
			desc:    "invalid json object",
			input:   `:"Developer"`,
			want:    &metadata.Person{},
			wantErr: cmpopts.AnyError,
		},
		{
			desc:  "full person object",
			input: `{"name":"Developer","email":"dev@corp.com","url":"http://dev.blog.com"}`,
			want: &metadata.Person{
				Name:  "Developer",
				Email: "dev@corp.com",
				URL:   "http://dev.blog.com",
			},
		},
		{
			desc:  "person object no name",
			input: `{"email":"dev@corp.com","url":"http://dev.blog.com"}`,
			want:  &metadata.Person{},
		},
		{
			desc:  "person object no email",
			input: `{"name":"Developer","url":"http://dev.blog.com"}`,
			want: &metadata.Person{
				Name: "Developer",
				URL:  "http://dev.blog.com",
			},
		},
		{
			desc:  "person object no url",
			input: `{"name":"Developer","email":"dev@corp.com"}`,
			want: &metadata.Person{
				Name:  "Developer",
				Email: "dev@corp.com",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			p := &metadata.Person{}
			if err := p.UnmarshalJSON([]byte(tc.input)); !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("UnmarshalJSON(%+v) error: got %v, want %v\n", tc.input, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, p); diff != "" {
				t.Errorf("UnmarshalJSON(%+v) diff (-want +got):\n%s", tc.input, diff)
			}
		})
	}
}

func TestPersonString(t *testing.T) {
	testCases := []struct {
		desc  string
		input *metadata.Person
		want  string
	}{
		{
			desc:  "nil input",
			input: nil,
			want:  "",
		},
		{
			desc: "person_with_no_name",
			input: &metadata.Person{
				Email: "dev@corp.com",
				URL:   "http://dev.blog.com",
			},
			want: "",
		},
		{
			desc: "person_with_no_email",
			input: &metadata.Person{
				Name: "Developer",
				URL:  "http://dev.blog.com",
			},
			want: "Developer (http://dev.blog.com)",
		},
		{
			desc: "person_with_no_url",
			input: &metadata.Person{
				Name:  "Developer",
				Email: "dev@corp.com",
			},
			want: "Developer <dev@corp.com>",
		},
		{
			desc: "person_object",
			input: &metadata.Person{
				Name:  "Developer",
				Email: "dev@corp.com",
				URL:   "http://dev.blog.com",
			},
			want: "Developer <dev@corp.com> (http://dev.blog.com)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := tc.input.PersonString()
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("metadata.PersonString(%+v) diff (-want +got):\n%s", tc.input, diff)
			}
		})
	}
}

func TestPersonFromString(t *testing.T) {
	testCases := []struct {
		desc  string
		input string
		want  *metadata.Person
	}{
		{
			desc:  "empty input",
			input: "",
			want:  nil,
		},
		{
			desc:  "name, email, and url",
			input: "Developer <dev@corp.com> (http://dev.blog.com)",
			want: &metadata.Person{
				Name:  "Developer",
				Email: "dev@corp.com",
				URL:   "http://dev.blog.com",
			},
		},
		{
			desc:  "name, and url",
			input: "Developer (http://dev.blog.com)",
			want: &metadata.Person{
				Name: "Developer",
				URL:  "http://dev.blog.com",
			},
		},
		{
			desc:  "name, email",
			input: "Developer <dev@corp.com>",
			want: &metadata.Person{
				Name:  "Developer",
				Email: "dev@corp.com",
			},
		},
		{
			desc:  "name only",
			input: "Developer",
			want: &metadata.Person{
				Name: "Developer",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := metadata.PersonFromString(tc.input)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("metadata.PersonFromString(%+v) diff (-want +got):\n%s", tc.input, diff)
			}
		})
	}
}

func TestToProto(t *testing.T) {
	testCases := []struct {
		desc string
		m    *metadata.JavascriptPackageJSONMetadata
		want *pb.JavascriptPackageJSONMetadata
	}{
		{
			desc: "set_metadata",
			m: &metadata.JavascriptPackageJSONMetadata{
				Author: &metadata.Person{
					Name:  "some-author",
					Email: "some-author@google.com",
				},
				Source: metadata.Unknown,
			},
			want: &pb.JavascriptPackageJSONMetadata{
				Author: "some-author <some-author@google.com>",
				Source: pb.PackageSource_UNKNOWN,
			},
		},
		{
			desc: "set_all_fields",
			m: &metadata.JavascriptPackageJSONMetadata{
				Author: &metadata.Person{
					Name:  "some-author",
					Email: "some-author@google.com",
				},
				Maintainers: []*metadata.Person{
					{
						Name:  "first-maintainer",
						Email: "first-maintainer@google.com",
					},
					{
						Name:  "second-maintainer",
						Email: "second-maintainer@google.com",
					},
				},
				Contributors: []*metadata.Person{
					{
						Name:  "first-contributor",
						Email: "first-contributor@google.com",
					},
					{
						Name:  "second-contributor",
						Email: "second-contributor@google.com",
					},
				},
				Source: metadata.PublicRegistry,
			},
			want: &pb.JavascriptPackageJSONMetadata{
				Author: "some-author <some-author@google.com>",
				Maintainers: []string{
					"first-maintainer <first-maintainer@google.com>",
					"second-maintainer <second-maintainer@google.com>",
				},
				Contributors: []string{
					"first-contributor <first-contributor@google.com>",
					"second-contributor <second-contributor@google.com>",
				},
				Source: pb.PackageSource_PUBLIC_REGISTRY,
			},
		},
		{
			desc: "set_public_registry_NPMResolutionSource",
			m: &metadata.JavascriptPackageJSONMetadata{
				Author: &metadata.Person{
					Name:  "some-author",
					Email: "some-author@google.com",
				},
				Source: metadata.PublicRegistry,
			},
			want: &pb.JavascriptPackageJSONMetadata{
				Author: "some-author <some-author@google.com>",
				Source: pb.PackageSource_PUBLIC_REGISTRY,
			},
		},
		{
			desc: "set_other_NPMResolutionSource",
			m: &metadata.JavascriptPackageJSONMetadata{
				Author: &metadata.Person{
					Name:  "some-author",
					Email: "some-author@google.com",
				},
				Source: metadata.Other,
			},
			want: &pb.JavascriptPackageJSONMetadata{
				Author: "some-author <some-author@google.com>",
				Source: pb.PackageSource_OTHER,
			},
		},
		{
			desc: "set_local_NPMResolutionSource",
			m: &metadata.JavascriptPackageJSONMetadata{
				Author: &metadata.Person{
					Name:  "some-author",
					Email: "some-author@google.com",
				},
				Source: metadata.Local,
			},
			want: &pb.JavascriptPackageJSONMetadata{
				Author: "some-author <some-author@google.com>",
				Source: pb.PackageSource_LOCAL,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := metadata.ToProto(tc.m)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.want, got, opts...); diff != "" {
				t.Errorf("metadata.ToProto(%+v): (-want +got):\n%s", tc.m, diff)
			}

			// Test the reverse conversion for completeness.
			gotStruct := metadata.ToStruct(got)
			if diff := cmp.Diff(tc.m, gotStruct); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", got, diff)
			}
		})
	}
}

func TestToStruct(t *testing.T) {
	testCases := []struct {
		desc string
		m    *pb.JavascriptPackageJSONMetadata
		want *metadata.JavascriptPackageJSONMetadata
	}{
		{
			desc: "some_fields",
			m: &pb.JavascriptPackageJSONMetadata{
				Author: "some-author",
			},
			want: &metadata.JavascriptPackageJSONMetadata{
				Author: &metadata.Person{
					Name: "some-author",
				},
				Source: metadata.Unknown,
			},
		},
		{
			desc: "all_fields",
			m: &pb.JavascriptPackageJSONMetadata{
				Author: "some-author <some-author@google.com>",
				Maintainers: []string{
					"first-maintainer <first-maintainer@google.com>",
					"second-maintainer <second-maintainer@google.com>",
				},
				Contributors: []string{
					"first-contributor <first-contributor@google.com>",
					"second-contributor <second-contributor@google.com>",
				},
				Source: pb.PackageSource_PUBLIC_REGISTRY,
			},
			want: &metadata.JavascriptPackageJSONMetadata{
				Author: &metadata.Person{
					Name:  "some-author",
					Email: "some-author@google.com",
				},
				Contributors: []*metadata.Person{
					{
						Name:  "first-contributor",
						Email: "first-contributor@google.com",
					},
					{
						Name:  "second-contributor",
						Email: "second-contributor@google.com",
					},
				},
				Maintainers: []*metadata.Person{
					{
						Name:  "first-maintainer",
						Email: "first-maintainer@google.com",
					},
					{
						Name:  "second-maintainer",
						Email: "second-maintainer@google.com",
					},
				},
				Source: metadata.PublicRegistry,
			},
		},
		{
			desc: "set_public_registry_NPMResolutionSource",
			m: &pb.JavascriptPackageJSONMetadata{
				Author: "some-author <some-author@google.com>",
				Source: pb.PackageSource_PUBLIC_REGISTRY,
			},
			want: &metadata.JavascriptPackageJSONMetadata{
				Author: &metadata.Person{
					Name:  "some-author",
					Email: "some-author@google.com",
				},
				Source: metadata.PublicRegistry,
			},
		},
		{
			desc: "set_other_NPMResolutionSource",
			m: &pb.JavascriptPackageJSONMetadata{
				Author: "some-author <some-author@google.com>",
				Source: pb.PackageSource_OTHER,
			},
			want: &metadata.JavascriptPackageJSONMetadata{
				Author: &metadata.Person{
					Name:  "some-author",
					Email: "some-author@google.com",
				},
				Source: metadata.Other,
			},
		},
		{
			desc: "set_local_NPMResolutionSource",
			m: &pb.JavascriptPackageJSONMetadata{
				Author: "some-author <some-author@google.com>",
				Source: pb.PackageSource_LOCAL,
			},
			want: &metadata.JavascriptPackageJSONMetadata{
				Author: &metadata.Person{
					Name:  "some-author",
					Email: "some-author@google.com",
				},
				Source: metadata.Local,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := metadata.ToStruct(tc.m)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", tc.m, diff)
			}

			if tc.m == nil {
				return
			}

			// Test the reverse conversion for completeness.
			gotProto := metadata.ToProto(got)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.m, gotProto, opts...); diff != "" {
				t.Errorf("metadata.ToProto(%+v): (-want +got):\n%s", got, diff)
			}
		})
	}
}
