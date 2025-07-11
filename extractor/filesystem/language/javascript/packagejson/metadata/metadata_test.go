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
