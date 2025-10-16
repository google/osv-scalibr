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

package metadata_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson/metadata"
	"google.golang.org/protobuf/proto"
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
			desc: "person with no name",
			input: &metadata.Person{
				Email: "dev@corp.com",
				URL:   "http://dev.blog.com",
			},
			want: "",
		},
		{
			desc: "person with no email",
			input: &metadata.Person{
				Name: "Developer",
				URL:  "http://dev.blog.com",
			},
			want: "Developer (http://dev.blog.com)",
		},
		{
			desc: "person with no url",
			input: &metadata.Person{
				Name:  "Developer",
				Email: "dev@corp.com",
			},
			want: "Developer <dev@corp.com>",
		},
		{
			desc: "person object",
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

func TestSetProto(t *testing.T) {
	testCases := []struct {
		desc string
		m    *metadata.JavascriptPackageJSONMetadata
		p    *pb.Package
		want *pb.Package
	}{
		{
			desc: "nil metadata",
			m:    nil,
			p:    &pb.Package{Name: "some-package"},
			want: &pb.Package{Name: "some-package"},
		},
		{
			desc: "nil package",
			m: &metadata.JavascriptPackageJSONMetadata{
				Author: &metadata.Person{
					Name:  "some-author",
					Email: "some-author@google.com",
				},
			},
			p:    nil,
			want: nil,
		},
		{
			desc: "set metadata",
			m: &metadata.JavascriptPackageJSONMetadata{
				Author: &metadata.Person{
					Name:  "some-author",
					Email: "some-author@google.com",
				},
				Source: metadata.Unknown,
			},
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_JavascriptMetadata{
					JavascriptMetadata: &pb.JavascriptPackageJSONMetadata{
						Author: "some-author <some-author@google.com>",
						Source: pb.PackageSource_UNKNOWN,
					},
				},
			},
		},
		{
			desc: "override metadata",
			m: &metadata.JavascriptPackageJSONMetadata{
				Author: &metadata.Person{
					Name:  "some-other-author",
					Email: "some-other-author@google.com",
				},
				Source: metadata.Unknown,
			},
			p: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_JavascriptMetadata{
					JavascriptMetadata: &pb.JavascriptPackageJSONMetadata{
						Author: "some-author <some-author@google.com>",
					},
				},
			},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_JavascriptMetadata{
					JavascriptMetadata: &pb.JavascriptPackageJSONMetadata{
						Author: "some-other-author <some-other-author@google.com>",
						Source: pb.PackageSource_UNKNOWN,
					},
				},
			},
		},
		{
			desc: "set all fields",
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
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_JavascriptMetadata{
					JavascriptMetadata: &pb.JavascriptPackageJSONMetadata{
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
			},
		},
		{
			desc: "set public registry NPMResolutionSource",
			m: &metadata.JavascriptPackageJSONMetadata{
				Author: &metadata.Person{
					Name:  "some-author",
					Email: "some-author@google.com",
				},
				Source: metadata.PublicRegistry,
			},
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_JavascriptMetadata{
					JavascriptMetadata: &pb.JavascriptPackageJSONMetadata{
						Author: "some-author <some-author@google.com>",
						Source: pb.PackageSource_PUBLIC_REGISTRY,
					},
				},
			},
		},
		{
			desc: "set other NPMResolutionSource",
			m: &metadata.JavascriptPackageJSONMetadata{
				Author: &metadata.Person{
					Name:  "some-author",
					Email: "some-author@google.com",
				},
				Source: metadata.Other,
			},
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_JavascriptMetadata{
					JavascriptMetadata: &pb.JavascriptPackageJSONMetadata{
						Author: "some-author <some-author@google.com>",
						Source: pb.PackageSource_OTHER,
					},
				},
			},
		},
		{
			desc: "set local NPMResolutionSource",
			m: &metadata.JavascriptPackageJSONMetadata{
				Author: &metadata.Person{
					Name:  "some-author",
					Email: "some-author@google.com",
				},
				Source: metadata.Local,
			},
			p: &pb.Package{Name: "some-package"},
			want: &pb.Package{
				Name: "some-package",
				Metadata: &pb.Package_JavascriptMetadata{
					JavascriptMetadata: &pb.JavascriptPackageJSONMetadata{
						Author: "some-author <some-author@google.com>",
						Source: pb.PackageSource_LOCAL,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			p := proto.Clone(tc.p).(*pb.Package)
			tc.m.SetProto(p)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(tc.want, p, opts...); diff != "" {
				t.Errorf("Metatadata{%+v}.SetProto(%+v): (-want +got):\n%s", tc.m, tc.p, diff)
			}

			// Test the reverse conversion for completeness.

			if tc.p == nil && tc.want == nil {
				return
			}

			got := metadata.ToStruct(p.GetJavascriptMetadata())
			if diff := cmp.Diff(tc.m, got); diff != "" {
				t.Errorf("ToStruct(%+v): (-want +got):\n%s", p.GetJavascriptMetadata(), diff)
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
			desc: "nil",
			m:    nil,
			want: nil,
		},
		{
			desc: "some fields",
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
			desc: "all fields",
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
			desc: "set public registry NPMResolutionSource",
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
			desc: "set other NPMResolutionSource",
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
			desc: "set local NPMResolutionSource",
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

			gotP := &pb.Package{}
			wantP := &pb.Package{
				Metadata: &pb.Package_JavascriptMetadata{
					JavascriptMetadata: tc.m,
				},
			}
			got.SetProto(gotP)
			opts := []cmp.Option{
				protocmp.Transform(),
			}
			if diff := cmp.Diff(wantP, gotP, opts...); diff != "" {
				t.Errorf("Metatadata{%+v}.SetProto(%+v): (-want +got):\n%s", got, wantP, diff)
			}
		})
	}
}
