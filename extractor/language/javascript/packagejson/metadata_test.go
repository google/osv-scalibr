// Copyright 2024 Google LLC
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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor/language/javascript/packagejson"
)

func TestUnmarshalJSON_Person(t *testing.T) {
	testCases := []struct {
		desc    string
		input   string
		want    *packagejson.Person
		wantErr error
	}{
		{
			desc:  "empty person",
			input: `""`,
			want:  &packagejson.Person{},
		},
		{
			desc:  "full person string",
			input: `"Developer <dev@corp.com> (http://dev.blog.com)"`,
			want: &packagejson.Person{
				Name:  "Developer",
				Email: "dev@corp.com",
				URL:   "http://dev.blog.com",
			},
		},
		{
			desc:  "person string no name",
			input: `"<dev@corp.com> (http://dev.blog.com)"`,
			want:  &packagejson.Person{},
		},
		{
			desc:  "person string no email",
			input: `"Developer (http://dev.blog.com)"`,
			want: &packagejson.Person{
				Name: "Developer",
				URL:  "http://dev.blog.com",
			},
		},
		{
			desc:  "person string no url",
			input: `"Developer <dev@corp.com>"`,
			want: &packagejson.Person{
				Name:  "Developer",
				Email: "dev@corp.com",
			},
		},
		{
			desc:  "empty person object",
			input: `{}`,
			want:  &packagejson.Person{},
		},
		{
			desc:    "invalid json object",
			input:   `:"Developer"`,
			want:    &packagejson.Person{},
			wantErr: cmpopts.AnyError,
		},
		{
			desc:  "full person object",
			input: `{"name":"Developer","email":"dev@corp.com","url":"http://dev.blog.com"}`,
			want: &packagejson.Person{
				Name:  "Developer",
				Email: "dev@corp.com",
				URL:   "http://dev.blog.com",
			},
		},
		{
			desc:  "person object no name",
			input: `{"email":"dev@corp.com","url":"http://dev.blog.com"}`,
			want:  &packagejson.Person{},
		},
		{
			desc:  "person object no email",
			input: `{"name":"Developer","url":"http://dev.blog.com"}`,
			want: &packagejson.Person{
				Name: "Developer",
				URL:  "http://dev.blog.com",
			},
		},
		{
			desc:  "person object no url",
			input: `{"name":"Developer","email":"dev@corp.com"}`,
			want: &packagejson.Person{
				Name:  "Developer",
				Email: "dev@corp.com",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			p := &packagejson.Person{}
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
		input *packagejson.Person
		want  string
	}{
		{
			desc:  "nil input",
			input: nil,
			want:  "",
		},
		{
			desc: "person with no name",
			input: &packagejson.Person{
				Email: "dev@corp.com",
				URL:   "http://dev.blog.com",
			},
			want: "",
		},
		{
			desc: "person with no email",
			input: &packagejson.Person{
				Name: "Developer",
				URL:  "http://dev.blog.com",
			},
			want: "Developer (http://dev.blog.com)",
		},
		{
			desc: "person with no url",
			input: &packagejson.Person{
				Name:  "Developer",
				Email: "dev@corp.com",
			},
			want: "Developer <dev@corp.com>",
		},
		{
			desc: "person object",
			input: &packagejson.Person{
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
				t.Errorf("packagejson.PersonString(%+v) diff (-want +got):\n%s", tc.input, diff)
			}
		})
	}
}
