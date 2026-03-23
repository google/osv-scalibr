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

package apk

import (
	"maps"
	"runtime"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestExtractApkCache(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("Test skipped, OS unsupported: %v", runtime.GOOS)
	}
	tests := []struct {
		name string
		// fakeFS tarballs inner structure is represented using nested txtar
		fakeFS  string
		wantErr error
		want    []string
	}{
		{
			name: "valid",
			fakeFS: `
-- etc/apk/arch --
aarch64
-- etc/apk/repositories --
https://dl-cdn.alpinelinux.org/alpine/v3.23/community
-- var/cache/apk/APKINDEX.ee9ee731.tar.gz --
== APKINDEX ==
C:Q1c2f3...
P:curl
V:8.1.2-r0

C:Q4d5e6...
P:openssl
V:3.1.0-r0
== DESCRIPTION ==
v3.23.3-260-gd483e0429d3
`,
			wantErr: nil,
			want:    []string{"curl:8.1.2-r0", "openssl:3.1.0-r0"},
		},
		{
			name: "missing_cache_entirely",
			fakeFS: `
-- etc/apk/arch --
aarch64
-- etc/apk/repositories --
https://dl-cdn.alpinelinux.org/alpine/v3.23/community
`,
			wantErr: ErrOutOfSyncCache,
		},
		{
			name: "missing_arch_file",
			fakeFS: `
-- etc/apk/repositories --
https://dl-cdn.alpinelinux.org/alpine/v3.23/community
-- var/cache/apk/APKINDEX.caefdf39.tar.gz --
== APKINDEX ==
P:curl
`,
			wantErr: cmpopts.AnyError,
		},
		{
			// The etc/apk/repositories file has been modified but
			// the cache has not been refreshed
			name: "comment_repository_ignored",
			fakeFS: `
-- etc/apk/arch --
aarch64
-- etc/apk/repositories --
#https://dl-cdn.alpinelinux.org/alpine/v3.23/community
https://dl-cdn.alpinelinux.org/alpine/v3.24/community
-- var/cache/apk/APKINDEX.caefdf39.tar.gz --
== APKINDEX ==
P:curl
`,
			wantErr: ErrOutOfSyncCache,
		},
		{
			name: "multiple_repositories",
			fakeFS: `
-- etc/apk/arch --
aarch64
-- etc/apk/repositories --
https://dl-cdn.alpinelinux.org/alpine/v3.23/main
https://dl-cdn.alpinelinux.org/alpine/v3.23/community
https://pkgs.orb.net/stable/alpine
-- var/cache/apk/APKINDEX.caefdf39.tar.gz --
== APKINDEX ==
P:curl
V:8.1.2-r0
-- var/cache/apk/APKINDEX.ee9ee731.tar.gz --
== APKINDEX ==
P:nano
V:2.1
-- var/cache/apk/APKINDEX.b3dcc868.tar.gz --
== APKINDEX ==
P:orb
V:3.4
`,
			want: []string{"curl:8.1.2-r0", "nano:2.1"},
		},
		{
			name: "tagged_repository",
			fakeFS: `
-- etc/apk/arch --
aarch64
-- etc/apk/repositories --
https://dl-cdn.alpinelinux.org/alpine/v3.23/main
@comm https://dl-cdn.alpinelinux.org/alpine/v3.23/community
-- var/cache/apk/APKINDEX.caefdf39.tar.gz --
== APKINDEX ==
P:curl
V:8.1.2-r0
-- var/cache/apk/APKINDEX.ee9ee731.tar.gz --
== APKINDEX ==
P:nano
V:2.1
`,
			want: []string{"curl:8.1.2-r0", "nano:2.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFS, err := fakefs.PrepareFS(tt.fakeFS, fakefs.TarGzModifier)
			if err != nil {
				t.Fatalf("failed to prepare fakefs: %v", err)
			}

			scanRoot := &fs.ScanRoot{FS: mockFS}
			gotCache, err := extractApkCache(scanRoot)

			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("extractAptCache() error mismatch (-want +got):\n%s", diff)
			}

			got := []string{}
			if gotCache != nil {
				got = slices.Sorted(maps.Keys(gotCache.value))
			}

			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("extractAptCache() (-want +got): %v", diff)
			}
		})
	}
}
