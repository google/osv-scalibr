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

package flatjson_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/veles/secrets/common/flatjson"
)

type testExtractorSubCase struct {
	name  string
	input string
	want  map[string]string
}

func TestExtractor(t *testing.T) {
	cases := []struct {
		name     string
		required []string
		optional []string
		subs     []testExtractorSubCase
	}{
		{
			name:     "no keys",
			required: []string{},
			optional: []string{},
			subs: []testExtractorSubCase{
				{
					name:  "empty",
					input: "",
					want:  map[string]string{},
				},
				{
					name:  "non-empty",
					input: `{"key1": "value1", "key2": "value2"}`,
					want:  map[string]string{},
				},
			},
		},
		{
			name:     "only required",
			required: []string{"foo", "bar", "baz"},
			optional: []string{},
			subs: []testExtractorSubCase{
				{
					name:  "empty",
					input: "",
					want:  nil,
				},
				{
					name:  "required key missing",
					input: `{"foo": "hello", "bar": "world"}`,
					want:  nil,
				},
				{
					name:  "all present",
					input: `{"foo": "hello", "bar": "world", "baz": "12345"}`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
						"baz": "12345",
					},
				},
				{
					name:  "extra keys ignored",
					input: `{"foo": "hello", "bar": "world", "baz": "12345", "another": "ignored"}`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
						"baz": "12345",
					},
				},
			},
		},
		{
			name:     "only optional",
			required: []string{},
			optional: []string{"foo", "bar", "baz"},
			subs: []testExtractorSubCase{
				{
					name:  "empty",
					input: "",
					want:  map[string]string{},
				},
				{
					name:  "subset present",
					input: `{"foo": "hello", "bar": "world"}`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
					},
				},
				{
					name:  "all present",
					input: `{"foo": "hello", "bar": "world", "baz": "12345"}`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
						"baz": "12345",
					},
				},
				{
					name:  "extra keys ignored",
					input: `{"foo": "hello", "bar": "world", "baz": "12345", "another": "ignored"}`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
						"baz": "12345",
					},
				},
			},
		},
		{
			name:     "required and optional",
			required: []string{"foo", "bar"},
			optional: []string{"baz", "another"},
			subs: []testExtractorSubCase{
				{
					name:  "empty",
					input: "",
					want:  nil,
				},
				{
					name:  "missing required",
					input: `{"foo": "hello", "baz": "meh"}`,
					want:  nil,
				},
				{
					name:  "only required",
					input: `{"foo": "hello", "bar": "world"}`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
					},
				},
				{
					name:  "required and some optional",
					input: `{"foo": "hello", "bar": "world", "baz": "12345"}`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
						"baz": "12345",
					},
				},
				{
					name:  "required and optional",
					input: `{"foo": "hello", "bar": "world", "baz": "12345", "another": "null"}`,
					want: map[string]string{
						"foo":     "hello",
						"bar":     "world",
						"baz":     "12345",
						"another": "null",
					},
				},
			},
		},
		{
			name:     "only supports string values",
			required: []string{"foo", "bar"},
			optional: []string{"baz"},
			subs: []testExtractorSubCase{
				{
					name:  "required is int",
					input: `{"foo": "hello", "bar": 12345, "baz": "nooo"}`,
					want:  nil,
				},
				{
					name:  "optional is int",
					input: `{"foo": "hello", "bar": "world", "baz": 12345}`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
					},
				},
				{
					name:  "unused is int",
					input: `{"foo": "hello", "bar": "world", "unused": 12345}`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
					},
				},
				{
					name:  "required is null",
					input: `{"foo": null, "bar": 12345, "baz": "nooo"}`,
					want:  nil,
				},
				{
					name:  "required is bool",
					input: `{"foo": false, "bar": 12345, "baz": "nooo"}`,
					want:  nil,
				},
				{
					name:  "required is array",
					input: `{"foo": [1, 2, 3], "bar": 12345, "baz": "nooo"}`,
					want:  nil,
				},
				{
					name:  "required is object",
					input: `{"foo": {"a": "b"}, "bar": 12345, "baz": "nooo"}`,
					want:  nil,
				},
				{
					name:  "optional is null",
					input: `{"foo": "hello", "bar": "world", "baz": null}`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
					},
				},
				{
					name:  "optional is bool",
					input: `{"foo": "hello", "bar": "world", "baz": true}`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
					},
				},
				{
					name:  "optional is array",
					input: `{"foo": "hello", "bar": "world", "baz": [1, 2, 3]}`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
					},
				},
				{
					name:  "optional is object",
					input: `{"foo": "hello", "bar": "world", "baz": {"a": "b"}}`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
					},
				},
			},
		},
		{
			name:     "robustness checks",
			required: []string{"foo", "bar"},
			optional: []string{"baz"},
			subs: []testExtractorSubCase{
				{
					name:  "order independent",
					input: `{"baz": "12345", "bar": "world", "foo": "hello"}`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
						"baz": "12345",
					},
				},
				{
					// This is not valid JSON. The extractor can still parse it, however.
					name:  "trailing comma",
					input: `{"foo": "hello", "bar": "world", "baz": "12345",}`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
						"baz": "12345",
					},
				},
				{
					name:  "nested",
					input: `{"key": {"baz": "12345", "bar": "world", "foo": "hello"}}`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
						"baz": "12345",
					},
				},
				{
					name: "multiline",
					input: `{
	"baz": "12345",
	"bar": "world",
	"foo": "hello"
}`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
						"baz": "12345",
					},
				},
				{
					// This is not valid JSON. The extractor can still parse it, however.
					name: "multiline_trailing_comma",
					input: `{
	"baz": "12345",
	"bar": "world",
	"foo": "hello",
}`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
						"baz": "12345",
					},
				},
				{
					name:  "escaped",
					input: `"{\n  \"foo\": \"hello\",\n  \"bar\": \"world\"\n}"`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
					},
				},
				{
					name:  "twice escaped",
					input: `"\"{\\n  \\\"foo\\\": \\\"hello\\\",\\n  \\\"bar\\\": \\\"world\\\"\\n}"`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
					},
				},
				{
					name:  "four times escaped",
					input: `"\"\\\"\\\\\\\"{\\\\\\\\\\\\\\\"foo\\\\\\\\\\\\\\\":\\\\\\\\\\\\\\\"hello-world\\\\\\\\\\\\\\\",\\\\\\\\\\\\\\\"bar\\\\\\\\\\\\\\\":\\\\\\\\\\\\\\\"my@friend\\\\\\\\\\\\\\\"}\\\\\\\"\\\"\""`,
					want: map[string]string{
						"foo": "hello-world",
						"bar": "my@friend",
					},
				},
				{
					name:  "preserves whitespace in value",
					input: `{"foo": "hello\nworld", "bar": "my friend"}`,
					want: map[string]string{
						"foo": "hello\nworld",
						"bar": "my friend",
					},
				},
				{
					name:  "preserves whitespace in value when escaped",
					input: `"{\n  \"foo\": \"hello\\nworld\",\n  \"bar\": \"my friend\"\n}"`,
					want: map[string]string{
						"foo": "hello\nworld",
						"bar": "my friend",
					},
				},
				{
					name: "different_whitespace_after_colon",
					input: `{
	"baz":  "12345",
	"bar":	"world",
	"foo":
	"hello"
}`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
						"baz": "12345",
					},
				},
				{
					name:  "surrounding braces not required",
					input: `"foo": "hello", "bar": "world", "baz": "12345",`,
					want: map[string]string{
						"foo": "hello",
						"bar": "world",
						"baz": "12345",
					},
				},
			},
		},
		{
			name:     "limitations",
			required: []string{"foo"},
			optional: []string{},
			subs: []testExtractorSubCase{
				{
					name:  "single quotes for key",
					input: `{'foo': "hello"}`,
					want:  nil,
				},
				{
					name:  "single quotes for value",
					input: `{"foo": 'hello'}`,
					want:  nil,
				},
				{
					name:  "single quotes for both",
					input: `{'foo': 'hello'}`,
					want:  nil,
				},
				{
					name:  "separator not colon",
					input: `"foo"="hello"`,
					want:  nil,
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ex := flatjson.NewExtractor(tc.required, tc.optional)
			for _, sc := range tc.subs {
				t.Run(sc.name, func(t *testing.T) {
					t.Parallel()
					got := ex.Extract([]byte(sc.input))
					if diff := cmp.Diff(sc.want, got); diff != "" {
						t.Errorf("Extract() diff (-want +got):\n%s", diff)
					}
				})
			}
		})
	}
}
