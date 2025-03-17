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

package fakeextractor_test

import (
	"context"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/testing/fakeextractor"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestName(t *testing.T) {
	tests := []struct {
		name      string
		extractor filesystem.Extractor
		want      string
	}{
		{
			name:      "no name",
			extractor: fakeextractor.New("", 1, nil, nil),
			want:      "",
		},
		{
			name:      "name",
			extractor: fakeextractor.New("some extractor", 1, nil, nil),
			want:      "some extractor",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.extractor.Name()
			if got != test.want {
				t.Fatalf("extractor.Name() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	tests := []struct {
		name      string
		extractor filesystem.Extractor
		want      int
	}{
		{
			name:      "zero version",
			extractor: fakeextractor.New("", 0, nil, nil),
			want:      0,
		},
		{
			name:      "positive version",
			extractor: fakeextractor.New("some extractor", 7, nil, nil),
			want:      7,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.extractor.Version()
			if got != test.want {
				t.Fatalf("extractor.Version() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestFileRequired(t *testing.T) {
	type args struct {
		path string
		mode fs.FileMode
	}

	tests := []struct {
		name      string
		extractor filesystem.Extractor
		args      args
		want      bool
	}{
		{
			name:      "file required",
			extractor: fakeextractor.New("", 1, []string{"some file", "another file"}, nil),
			args:      args{"some file", fs.ModePerm},
			want:      true,
		},
		{
			name:      "file not required because none are required by extractor",
			extractor: fakeextractor.New("", 1, nil, nil),
			args:      args{"some file", fs.ModePerm},
			want:      false,
		},
		{
			name:      "file not the same as required files",
			extractor: fakeextractor.New("", 1, []string{"some file", "another file"}, nil),
			args:      args{"yet another file", fs.ModePerm},
			want:      false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.extractor.FileRequired(simplefileapi.New(test.args.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(test.args.path),
				FileMode: test.args.mode,
			}))
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Fatalf("extractor.FileRequired(%v, %v) returned unexpected result; diff (-want +got):\n%s", test.args.path, test.args.mode, diff)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	name1 := "package"
	name2 := "another package"
	multipleInventories := []*extractor.Inventory{{
		Name:      name1,
		Locations: []string{"some path"},
	}, {
		Name:      name2,
		Locations: []string{"some path"},
	}}

	type args struct {
		//nolint:containedctx
		ctx   context.Context
		input *filesystem.ScanInput
	}
	tests := []struct {
		name      string
		extractor filesystem.Extractor
		args      args
		want      []*extractor.Inventory
		wantErr   error
	}{
		{
			name: "no results",
			extractor: fakeextractor.New("", 1, nil, map[string]fakeextractor.NamesErr{
				"some path": {nil, nil},
			}),
			args: args{t.Context(), &filesystem.ScanInput{Path: "some path"}},
			want: []*extractor.Inventory{},
		},
		{
			name: "multiple results",
			extractor: fakeextractor.New("extractor name", 1, nil, map[string]fakeextractor.NamesErr{
				"some path": {[]string{name1, name2}, nil},
			}),
			args: args{t.Context(), &filesystem.ScanInput{Path: "some path"}},
			want: multipleInventories,
		},
		{
			name: "unrecognized path throws an error",
			extractor: fakeextractor.New("", 1, nil, map[string]fakeextractor.NamesErr{
				"some path": {nil, nil},
			}),
			args:    args{t.Context(), &filesystem.ScanInput{Path: "another path"}},
			wantErr: cmpopts.AnyError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.extractor.Extract(test.args.ctx, test.args.input)
			if !cmp.Equal(err, test.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("extractor.Extract(%v, %+v) got error: %v, want: %v\n", test.args.ctx, test.args.input, err, test.wantErr)
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Fatalf("extractor.Extract(%v, %+v) returned unexpected result; diff (-want +got):\n%s", test.args.ctx, test.args.input, diff)
			}
		})
	}
}
