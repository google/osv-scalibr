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

package ecosystem_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/purl/ecosystem"
)

func TestFromPURL(t *testing.T) {
	tests := []struct {
		desc    string
		purlStr string
		want    string
	}{
		{
			desc:    "Alpine with version distro",
			purlStr: "pkg:apk/alpine/nginx@1.18.0?distro=v3.18",
			want:    "Alpine:v3.18",
		},
		{
			desc:    "Alpine with version distro (no v prefix)",
			purlStr: "pkg:apk/alpine/nginx@1.18.0?distro=3.18",
			want:    "Alpine:v3.18",
		},
		{
			desc:    "Alpine with version distro minor",
			purlStr: "pkg:apk/alpine/nginx@1.18.0?distro=v3.18.2",
			want:    "Alpine:v3.18",
		},
		{
			desc:    "Alpine with edge distro",
			purlStr: "pkg:apk/alpine/nginx@1.18.0?distro=edge",
			want:    "Alpine:edge",
		},
		{
			desc:    "Alpine with suffix distro (e.g. alpine-3.18)",
			purlStr: "pkg:apk/alpine/nginx@1.18.0?distro=alpine-3.18",
			want:    "Alpine:v3.18",
		},
		{
			desc:    "Alpine without distro",
			purlStr: "pkg:apk/alpine/nginx@1.18.0",
			want:    "Alpine",
		},
		{
			desc:    "Wolfi",
			purlStr: "pkg:apk/wolfi/nginx@1.18.0",
			want:    "Wolfi",
		},
		{
			desc:    "Chainguard",
			purlStr: "pkg:apk/chainguard/nginx@1.18.0",
			want:    "Chainguard",
		},
		{
			desc:    "Alpine with invalid distro version",
			purlStr: "pkg:apk/alpine/nginx@1.18.0?distro=bad",
			want:    "Alpine",
		},
		{
			desc:    "Alpine with invalid distro version (no minor)",
			purlStr: "pkg:apk/alpine/nginx@1.18.0?distro=v3",
			want:    "Alpine",
		},
		{
			desc:    "Wolfi with distro (should ignore distro)",
			purlStr: "pkg:apk/wolfi/nginx@1.18.0?distro=v3.18",
			want:    "Wolfi",
		},
		{
			desc:    "Debian with version",
			purlStr: "pkg:deb/debian/nginx@1.18.0?distro=11",
			want:    "Debian:11",
		},
		{
			desc:    "Debian with distro version (e.g. debian-11)",
			purlStr: "pkg:deb/debian/nginx@1.18.0?distro=debian-11",
			want:    "Debian:11",
		},
		{
			desc:    "Debian with codename (e.g. bookworm)",
			purlStr: "pkg:deb/debian/nginx@1.18.0?distro=bookworm",
			want:    "Debian:12",
		},
		{
			desc:    "Debian without distro",
			purlStr: "pkg:deb/debian/nginx@1.18.0",
			want:    "Debian",
		},
		{
			desc:    "Ubuntu with version",
			purlStr: "pkg:deb/ubuntu/nginx@1.18.0?distro=22.04",
			want:    "Ubuntu:22.04:LTS",
		},
		{
			desc:    "Ubuntu with codename (e.g. jammy)",
			purlStr: "pkg:deb/ubuntu/nginx@1.18.0?distro=jammy",
			want:    "Ubuntu:22.04:LTS",
		},
		{
			desc:    "Ubuntu with non-LTS codename (e.g. quantal)",
			purlStr: "pkg:deb/ubuntu/nginx@1.18.0?distro=quantal",
			want:    "Ubuntu:12.10",
		},
		{
			desc:    "Debian determined from distro prefix",
			purlStr: "pkg:deb/linux/nginx@1.18.0?distro=debian-11",
			want:    "Debian:11",
		},
		{
			desc:    "Ubuntu determined from distro prefix",
			purlStr: "pkg:deb/linux/nginx@1.18.0?distro=ubuntu-22.04",
			want:    "Ubuntu:22.04:LTS",
		},
		{
			desc:    "Debian determined from distro prefix without version",
			purlStr: "pkg:deb/linux/nginx@1.18.0?distro=debian",
			want:    "Debian:debian",
		},
		{
			desc:    "Ubuntu determined from distro prefix without version",
			purlStr: "pkg:deb/linux/nginx@1.18.0?distro=ubuntu",
			want:    "Ubuntu:ubuntu",
		},
		{
			desc:    "Debian determined from distro prefix with trailing dash",
			purlStr: "pkg:deb/linux/nginx@1.18.0?distro=debian-",
			want:    "Debian",
		},
		{
			desc:    "Ubuntu determined from distro prefix with trailing dash",
			purlStr: "pkg:deb/linux/nginx@1.18.0?distro=ubuntu-",
			want:    "Ubuntu",
		},
		{
			desc:    "Debian with sid distro",
			purlStr: "pkg:deb/debian/nginx@1.18.0?distro=sid",
			want:    "Debian:sid",
		},
		{
			desc:    "Debian with debian-sid distro",
			purlStr: "pkg:deb/debian/nginx@1.18.0?distro=debian-sid",
			want:    "Debian:sid",
		},
		{
			desc:    "Debian with experimental distro",
			purlStr: "pkg:deb/debian/nginx@1.18.0?distro=experimental",
			want:    "Debian:experimental",
		},
		{
			desc:    "Debian with unknown codename",
			purlStr: "pkg:deb/debian/nginx@1.18.0?distro=unknown",
			want:    "Debian:unknown",
		},
		{
			desc:    "Non-apk purl",
			purlStr: "pkg:npm/foo@1.0.0",
			want:    "",
		},
		{
			desc:    "Non-apk purl with distro (should ignore)",
			purlStr: "pkg:npm/foo@1.0.0?distro=v3.18",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			p, err := purl.FromString(tt.purlStr)
			if err != nil {
				t.Fatalf("purl.FromString(%q) returned error: %v", tt.purlStr, err)
			}
			got := ecosystem.FromPURL(&p)
			if diff := cmp.Diff(tt.want, got.String()); diff != "" {
				t.Errorf("FromPURL(%q) (-want +got):\n%s", tt.purlStr, diff)
			}
		})
	}
}
