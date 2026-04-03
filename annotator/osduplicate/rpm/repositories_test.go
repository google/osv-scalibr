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

package rpm

import (
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/testing/fakefs"
)

// compressModifier dynamically compresses fake files ending in .gz
func compressModifier(name string, f *fstest.MapFile) error {
	if !strings.HasSuffix(name, ".gz") {
		return nil
	}
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(f.Data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	f.Data = b.Bytes()
	return nil
}

// loadFixtureModifier dynamically loads a file content from a specific location
func loadFixtureModifier(name string, f *fstest.MapFile) error {
	const prefix = "LOAD_FIXTURE:"
	if after, ok := bytes.CutPrefix(f.Data, []byte(prefix)); ok {
		fixturePath := strings.TrimSpace(string(after))
		b, err := os.ReadFile(fixturePath)
		if err != nil {
			return err
		}
		f.Data = b
	}
	return nil
}

func TestIsMainDnfRepo(t *testing.T) {
	tests := []struct {
		osID    string
		dirName string
		want    bool
	}{
		// AlmaLinux / Rocky / CentOS Standard Repos
		{"almalinux", "appstream-993299b9f89b12a3", true},
		{"rocky", "baseos-12345", true},
		{"centos", "crb-abcd", true},
		// Third party repos (should fail)
		{"almalinux", "epel-993299b9f89b12a3", false},
		{"rocky", "docker-ce-stable-1234", false},
		// UBI exact formats
		{"rhel", "ubi-9-appstream-rpms-993299b9f89b12a3", true},
		{"rhel", "ubi-9-codeready-builder-rpms-abc", true},
		// Amazon Linux
		{"amzn", "amazonlinux-2023", true},
		{"amzn", "epel-123", false},
	}

	for _, tt := range tests {
		t.Run(tt.osID+"_"+tt.dirName, func(t *testing.T) {
			if got := isMainDnfRepo(tt.osID, tt.dirName); got != tt.want {
				t.Errorf("isMainDnfRepo(%q, %q) = %v, want %v", tt.osID, tt.dirName, got, tt.want)
			}
		})
	}
}

func TestIsMainYumRepo(t *testing.T) {
	tests := []struct {
		osID string
		repo string
		want bool
	}{
		// Amazon Linux
		{"amzn", "amzn2-core", true},
		{"amzn", "amzn2extra-docker", false},
		{"amzn", "epel", false},
		// CentOS
		{"centos", "base", true},
		{"centos", "repobase", true},
		{"centos", "updates", true},
		{"centos", "extras", false},
	}

	for _, tt := range tests {
		t.Run(tt.osID+"_"+tt.repo, func(t *testing.T) {
			if got := isMainYumRepo(tt.osID, tt.repo); got != tt.want {
				t.Errorf("isMainYumRepo(%q, %q) = %v, want %v", tt.osID, tt.repo, got, tt.want)
			}
		})
	}
}

func TestExtractMainRepos_VendorBypass(t *testing.T) {
	tests := []struct {
		name       string
		txt        string
		wantVendor []string
	}{
		{
			name: "RHEL bypasses cache and uses vendor string",
			txt: `
-- etc/os-release --
ID="rhel"
`,
			wantVendor: []string{"Red Hat, Inc."},
		},
		{
			name: "SLES bypasses cache and uses vendor string",
			txt: `
-- etc/os-release --
ID="sles_sap"
`,
			wantVendor: []string{"openSUSE", "SUSE LLC <https://www.suse.com/>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mfs, _ := fakefs.PrepareFS(tt.txt)
			root := &scalibrfs.ScanRoot{FS: mfs}

			got, err := extractMainRepos(root)
			if err != nil {
				t.Fatalf("extractMainRepos() error = %v", err)
			}

			if !got.vendorOnly {
				t.Errorf("Expected vendorOnly=true for bypass OS")
			}
			if diff := cmp.Diff(tt.wantVendor, got.trustedVendors); diff != "" {
				t.Errorf("trustedVendors mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExtractDnfMainRepos(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("Test skipped, OS unsupported: %v", runtime.GOOS)
	}

	tests := []struct {
		name    string
		osID    string
		txt     string
		want    *mainOSPackages
		wantErr error
	}{
		{
			name:    "Missing cache directory",
			osID:    "almalinux",
			txt:     ``,
			wantErr: ErrMissingCache,
		},
		{
			name: "Ignores 3rd party repos (epel)",
			osID: "almalinux",
			txt: `
-- etc/os-release --
ID="almalinux"
-- etc/dnf/dnf.conf --
-- var/cache/dnf/epel-12345/repodata/123-primary.xml.gz --
<metadata>
	<package type="rpm">
	  <name>golang</name>
	  <arch>aarch64</arch>
	  <version epoch="0" ver="1.25.3" rel="1.el9_7"/>
	  <checksum type="sha256" pkgid="YES">44584c65e7ae11893ff6c0535677aec5cd6c5cc31e34855e86904cc354ce6882</checksum>
	  <summary>The Go Programming Language</summary>
	  <description>The Go Programming Language.</description>
	  <packager>Rocky Linux Build System &lt;releng@rockylinux.org&gt;</packager>
	  <url>http://golang.org/</url>
	  <time file="1763663501" build="1763661517"/>
	  <size package="1310659" installed="10067264" archive="10081900"/>
	  <location href="Packages/g/golang-1.25.3-1.el9_7.aarch64.rpm"/>
	  <format>
	    <rpm:license>BSD and Public Domain</rpm:license>
	    <rpm:vendor>Rocky Enterprise Software Foundation</rpm:vendor>
	    <rpm:group>Unspecified</rpm:group>
	    <rpm:sourcerpm>golang-1.25.3-1.el9_7.src.rpm</rpm:sourcerpm>
	  </format>
	</package>
</metadata>
`,
			want: &mainOSPackages{
				value: map[string]struct{}{},
			},
		},
		{
			name: "Parses standard DNF primary.xml.gz correctly",
			osID: "almalinux",
			txt: `
-- etc/os-release --
ID="rocky"
-- etc/dnf/dnf.conf --
-- var/cache/dnf/appstream-12345/repodata/123-primary.xml.gz --
<metadata>
	<package type="rpm">
	  <name>golang</name>
	  <arch>aarch64</arch>
	  <version epoch="0" ver="1.25.3" rel="1.el9_7"/>
	  <checksum type="sha256" pkgid="YES">44584c65e7ae11893ff6c0535677aec5cd6c5cc31e34855e86904cc354ce6882</checksum>
	  <summary>The Go Programming Language</summary>
	  <description>The Go Programming Language.</description>
	  <packager>Rocky Linux Build System &lt;releng@rockylinux.org&gt;</packager>
	  <url>http://golang.org/</url>
	  <time file="1763663501" build="1763661517"/>
	  <size package="1310659" installed="10067264" archive="10081900"/>
	  <location href="Packages/g/golang-1.25.3-1.el9_7.aarch64.rpm"/>
	  <format>
	    <rpm:license>BSD and Public Domain</rpm:license>
	    <rpm:vendor>Rocky Enterprise Software Foundation</rpm:vendor>
	    <rpm:group>Unspecified</rpm:group>
	    <rpm:sourcerpm>golang-1.25.3-1.el9_7.src.rpm</rpm:sourcerpm>
	  </format>
	</package>
</metadata>
-- var/cache/dnf/baseos-abcde/repodata/456-primary.xml.gz --
<metadata>
  <package type="rpm">
    <name>bash</name>
    <arch>x86_64</arch>
    <version epoch="0" ver="5.1.8" rel="9.el9"/>
    <checksum type="sha256" pkgid="YES">32e2ba0bd3118ef85c88e7b99c855a82200dc89dbb1580f4f46cb0594348572b</checksum>
    <summary>The GNU Bourne Again shell</summary>
    <description>The GNU Bourne Again shell (Bash) is a shell or command language interpreter that is compatible with the Bourne shell (sh). Bash incorporates useful features from the Korn shell (ksh) and the C shell (csh). Most sh scripts can be run by bash without modification.</description>
    <packager>Rocky Linux Build System &lt;releng@rockylinux.org&gt;</packager>
    <url>https://www.gnu.org/software/bash</url>
    <time file="1710253450" build="1710188820"/>
    <size package="1855217" installed="7293504" archive="7309996"/>
    <location href="Packages/b/bash-5.1.8-9.el9.x86_64.rpm"/>
    <format>
      <rpm:license>GPLv3+</rpm:license>
      <rpm:vendor>Rocky Enterprise Software Foundation</rpm:vendor>
      <rpm:group>Unspecified</rpm:group>
      <rpm:buildhost>ord1-prod-x86build001.svc.aws.rockylinux.org</rpm:buildhost>
      <rpm:sourcerpm>bash-5.1.8-9.el9.src.rpm</rpm:sourcerpm>
      <rpm:header-range start="4504" end="68501"/>
      <rpm:provides>
        <rpm:entry name="/bin/bash"/>
        <rpm:entry name="/bin/sh"/>
        <rpm:entry name="bash" flags="EQ" epoch="0" ver="5.1.8" rel="9.el9"/>
        <rpm:entry name="bash(x86-64)" flags="EQ" epoch="0" ver="5.1.8" rel="9.el9"/>
      </rpm:provides>
    </format>
  </package>
</metadata>
`,
			want: &mainOSPackages{
				value: map[string]struct{}{
					"bash-5.1.8-9.el9.src.rpm":      {},
					"golang-1.25.3-1.el9_7.src.rpm": {},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mfs, err := fakefs.PrepareFS(tt.txt, compressModifier)
			if err != nil {
				t.Fatal(err)
			}
			root := &scalibrfs.ScanRoot{FS: mfs}

			got, err := extractDnfMainRepos(root, tt.osID)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("extractDnfMainRepos() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			opts := []cmp.Option{
				cmp.AllowUnexported(mainOSPackages{}),
				cmpopts.EquateEmpty(),
			}

			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("extractDnfMainRepos() (-want +got): %v", diff)
			}
		})
	}
}

func TestExtractYumMainRepos(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("Test skipped, OS unsupported: %v", runtime.GOOS)
	}

	tests := []struct {
		name    string
		osID    string
		txt     string
		want    *mainOSPackages
		wantErr error
	}{
		{
			name:    "Missing cache directory",
			osID:    "centos",
			txt:     ``,
			wantErr: ErrMissingCache,
		},
		{
			name: "Ignores 3rd party repos (epel)",
			osID: "centos",
			txt: `
-- etc/os-release --
ID="centos"
-- etc/yum/yum.conf --
-- var/cache/yum/x86_64/7/epel/repodata/123-primary.sqlite.gz --
LOAD_FIXTURE: testdata/yum-primary.sqlite.gz
`,
			want: &mainOSPackages{
				value: map[string]struct{}{},
			},
		},
		{
			name: "Parses standard YUM primary.sqlite.gz correctly",
			osID: "centos",
			txt: `
-- etc/os-release --
ID="centos"
-- etc/yum/yum.conf --
-- var/cache/yum/x86_64/7/base/repodata/456-primary.sqlite.gz --
LOAD_FIXTURE: testdata/yum-primary.sqlite.gz
`,
			want: &mainOSPackages{
				value: map[string]struct{}{
					"golang-1.13.14-1.amzn2.0.1.src.rpm": {},
					"curl-7.55.1-12.amzn2.0.6.src.rpm":   {},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mfs, err := fakefs.PrepareFS(tt.txt, loadFixtureModifier)
			if err != nil {
				t.Fatal(err)
			}
			root := &scalibrfs.ScanRoot{FS: mfs}

			got, err := extractYumMainRepos(root, tt.osID)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("extractYumMainRepos() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			opts := []cmp.Option{
				cmp.AllowUnexported(mainOSPackages{}),
				cmpopts.EquateEmpty(),
			}

			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("extractYumMainRepos() (-want +got): %v", diff)
			}
		})
	}
}
