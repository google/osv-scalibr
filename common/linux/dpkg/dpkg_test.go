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

package dpkg

import (
	"context"
	"errors"
	"io"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/common/linux/dpkg/testing/dpkgutil"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

func TestConffilePathIterator(t *testing.T) {
	tests := []struct {
		name      string
		conffiles map[string]string
		want      []string
		wantOpen  []string
	}{
		{
			name:      "empty info dir",
			conffiles: map[string]string{},
			want:      nil,
		},
		{
			name: "No conffiles files",
			conffiles: map[string]string{
				"foo.txt": "foocontents",
			},
			want: nil,
		},
		{
			name: "one empty conffiles file",
			conffiles: map[string]string{
				"foo.conffiles": "",
			},
			want: []string{""},
		},
		{
			name: "one conffiles file with lines",
			conffiles: map[string]string{
				"foo.conffiles": "/foo\n/bar",
			},
			want: []string{"/foo", "/bar"},
		},
		{
			name: "two conffiles files",
			conffiles: map[string]string{
				"foo.conffiles": "/foo\n/bar",
				"baz.conffiles": "/baz",
			},
			want: []string{"/foo", "/bar", "/baz"},
		},
		{
			name: "conffiles file with irrelevant files",
			conffiles: map[string]string{
				"foo.conffiles": "/foo\n/bar",
				"baz.txt":       "bazcontents",
			},
			want: []string{"/foo", "/bar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := dpkgutil.SetupDPKGInfo(t, tt.conffiles, false)
			fs := scalibrfs.RealFSScanRoot(root).FS

			it, err := NewConffilePathIterator(fs)
			if err != nil {
				t.Fatalf("NewConffilePathIterator() returned err: %v", err)
			}
			defer it.Close()

			var got []string
			for {
				path, err := it.Next(t.Context())
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("it.Next() returned err: %v", err)
				}
				got = append(got, path)
			}

			sort.Strings(got)
			sort.Strings(tt.want)

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ConffilePathIterator returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestConffilePathIteratorContextCancel(t *testing.T) {
	root := dpkgutil.SetupDPKGInfo(t, map[string]string{
		"foo.conffiles": "/foo\n/bar",
	}, false)
	fs := scalibrfs.RealFSScanRoot(root).FS

	ctx, cancel := context.WithCancel(t.Context())
	it, err := NewConffilePathIterator(fs)
	if err != nil {
		t.Fatalf("NewConffilePathIterator() returned err: %v", err)
	}
	defer it.Close()
	cancel()
	_, err = it.Next(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("it.Next() after context cancel: got err %v, want context.Canceled", err)
	}
}

func TestConffilePathIteratorMissingInfoDir(t *testing.T) {
	sfs := scalibrfs.RealFSScanRoot(t.TempDir()).FS
	it, err := NewConffilePathIterator(sfs)
	if err != nil {
		t.Fatalf("NewConffilePathIterator() with missing info dir: got err %v, want nil", err)
	}
	defer it.Close()
	_, err = it.Next(t.Context())
	if !errors.Is(err, io.EOF) {
		t.Errorf("it.Next() with missing info dir: got err %v, want io.EOF", err)
	}
}

func TestListFilePathIterator(t *testing.T) {
	tests := []struct {
		name     string
		list     map[string]string
		want     []string
		wantOpen []string
	}{
		{
			name: "empty info dir",
			list: map[string]string{},
			want: nil,
		},
		{
			name: "No list files",
			list: map[string]string{
				"foo.txt": "foocontents",
			},
			want: nil,
		},
		{
			name: "one empty list file",
			list: map[string]string{
				"foo.list": "",
			},
			want: []string{""},
		},
		{
			name: "one list file with lines",
			list: map[string]string{
				"foo.list": "/foo\n/bar",
			},
			want: []string{"/foo", "/bar"},
		},
		{
			name: "two list files",
			list: map[string]string{
				"foo.list": "/foo\n/bar",
				"baz.list": "/baz",
			},
			want: []string{"/foo", "/bar", "/baz"},
		},
		{
			name: "list file with irrelevant files",
			list: map[string]string{
				"foo.list": "/foo\n/bar",
				"baz.txt":  "bazcontents",
			},
			want: []string{"/foo", "/bar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := dpkgutil.SetupDPKGInfo(t, tt.list, false)
			fs := scalibrfs.RealFSScanRoot(root).FS

			it, err := NewListFilePathIterator(fs)
			if err != nil {
				t.Fatalf("NewFileIterator() returned err: %v", err)
			}
			defer it.Close()

			var got []string
			for {
				path, err := it.Next(t.Context())
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("it.Next() returned err: %v", err)
				}
				got = append(got, path)
			}

			sort.Strings(got)
			sort.Strings(tt.want)

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("FileIterator returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestListFilePathIteratorContextCancel(t *testing.T) {
	root := dpkgutil.SetupDPKGInfo(t, map[string]string{
		"foo.list": "/foo\n/bar",
	}, false)
	fs := scalibrfs.RealFSScanRoot(root).FS

	ctx, cancel := context.WithCancel(t.Context())
	it, err := NewListFilePathIterator(fs)
	if err != nil {
		t.Fatalf("NewFileIterator() returned err: %v", err)
	}
	defer it.Close()
	cancel()
	_, err = it.Next(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("it.Next() after context cancel: got err %v, want context.Canceled", err)
	}
}

func TestListFilePathIteratorMissingInfoDir(t *testing.T) {
	sfs := scalibrfs.RealFSScanRoot(t.TempDir()).FS
	it, err := NewListFilePathIterator(sfs)
	if err != nil {
		t.Fatalf("NewFileIterator() with missing info dir: got err %v, want nil", err)
	}
	defer it.Close()
	_, err = it.Next(t.Context())
	if !errors.Is(err, io.EOF) {
		t.Errorf("it.Next() with missing info dir: got err %v, want io.EOF", err)
	}
}
