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

package sshhole

import (
	"context"
	"encoding/binary"
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func makePkgIndex(t *testing.T, pkgs ...*extractor.Package) *packageindex.PackageIndex {
	t.Helper()
	px, err := packageindex.New(pkgs)
	if err != nil {
		t.Fatalf("packageindex.New() failed: %v", err)
	}
	return px
}

func osPkg(name, version string) *extractor.Package {
	return &extractor.Package{
		Name:    name,
		Version: version,
	}
}

func apkPkg(name, version string) *extractor.Package {
	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purl.TypeApk,
	}
}

// errOnOpenFS returns err when the file at failPath is opened.
type errOnOpenFS struct {
	fstest.MapFS

	failPath string
	err      error
}

func (e errOnOpenFS) Open(name string) (fs.File, error) {
	if name == e.failPath {
		return nil, &fs.PathError{Op: "open", Path: name, Err: e.err}
	}
	return e.MapFS.Open(name)
}

// minimalELFWithInterp constructs a valid 64-bit little-endian ELF binary with a
// .interp section set to interp and trailing banner data.
func minimalELFWithInterp(interp, banner string) []byte {
	shstrtab := []byte("\x00.shstrtab\x00.interp\x00")
	interpBytes := append([]byte(interp), 0)
	bannerBytes := []byte(banner)

	const ehdrSize = 64
	const shdrSize = 64
	const numShdrs = 3
	shoff := uint64(ehdrSize)
	shstrOff := shoff + numShdrs*shdrSize
	interpOff := shstrOff + uint64(len(shstrtab))
	bannerOff := interpOff + uint64(len(interpBytes))

	buf := make([]byte, bannerOff+uint64(len(bannerBytes)))
	// e_ident: magic, ELFCLASS64 (2), ELFDATA2LSB (1), EV_CURRENT (1)
	copy(buf[0:16], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	binary.LittleEndian.PutUint16(buf[16:18], 2)  // ET_EXEC
	binary.LittleEndian.PutUint16(buf[18:20], 62) // EM_X86_64
	binary.LittleEndian.PutUint32(buf[20:24], 1)  // EV_CURRENT
	binary.LittleEndian.PutUint64(buf[40:48], shoff)
	binary.LittleEndian.PutUint16(buf[52:54], ehdrSize)
	binary.LittleEndian.PutUint16(buf[58:60], shdrSize)
	binary.LittleEndian.PutUint16(buf[60:62], numShdrs)
	binary.LittleEndian.PutUint16(buf[62:64], 1) // e_shstrndx = section 1

	// Section 1: .shstrtab (name offset 1, SHT_STRTAB = 3)
	s1 := buf[ehdrSize+shdrSize : ehdrSize+2*shdrSize]
	binary.LittleEndian.PutUint32(s1[0:4], 1)
	binary.LittleEndian.PutUint32(s1[4:8], 3)
	binary.LittleEndian.PutUint64(s1[24:32], shstrOff)
	binary.LittleEndian.PutUint64(s1[32:40], uint64(len(shstrtab)))

	// Section 2: .interp (name offset 11, SHT_PROGBITS = 1)
	s2 := buf[ehdrSize+2*shdrSize : ehdrSize+3*shdrSize]
	binary.LittleEndian.PutUint32(s2[0:4], 11)
	binary.LittleEndian.PutUint32(s2[4:8], 1)
	binary.LittleEndian.PutUint64(s2[24:32], interpOff)
	binary.LittleEndian.PutUint64(s2[32:40], uint64(len(interpBytes)))

	copy(buf[shstrOff:], shstrtab)
	copy(buf[interpOff:], interpBytes)
	copy(buf[bannerOff:], bannerBytes)
	return buf
}

func TestDetectorMetadata(t *testing.T) {
	det, err := New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if det.Name() != "misc/sshhole" {
		t.Errorf("Name() = %q, want %q", det.Name(), "misc/sshhole")
	}
	if det.Version() != 0 {
		t.Errorf("Version() = %d, want 0", det.Version())
	}
	if diff := cmp.Diff(&plugin.Capabilities{}, det.Requirements()); diff != "" {
		t.Errorf("Requirements() unexpected diff (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{apk.Name}, det.RequiredExtractors()); diff != "" {
		t.Errorf("RequiredExtractors() unexpected diff (-want +got):\n%s", diff)
	}
	genericFindings := det.DetectedFinding().GenericFindings
	if len(genericFindings) != 1 || genericFindings[0].Adv == nil {
		t.Fatalf("DetectedFinding() = %+v, want 1 GenericFinding", det.DetectedFinding())
	}
	if got, want := genericFindings[0].Adv.ID.Publisher, "SCALIBR"; got != want {
		t.Errorf("DetectedFinding().Adv.ID.Publisher = %q, want %q", got, want)
	}
	if got, want := genericFindings[0].Adv.ID.Reference, "openssh-musl-authentication-bypass"; got != want {
		t.Errorf("DetectedFinding().Adv.ID.Reference = %q, want %q", got, want)
	}
}

func TestContainerScan(t *testing.T) {
	tests := []struct {
		name      string
		fsys      fstest.MapFS
		pkgs      []*extractor.Package
		wantFound bool
		wantExtra string
	}{
		{
			name: "vulnerable_standard_etc_shadow_with_sha512_salt",
			fsys: fstest.MapFS{
				"usr/sbin/sshd":       {Data: []byte("ELF-placeholder ld-musl-x86_64.so.1 OpenSSH_10.3p1")},
				"etc/ssh/sshd_config": {Data: []byte("# Default Alpine config\n")},
				"etc/passwd": {Data: []byte(
					"root:x:0:0:root:/root:/bin/sh\n" +
						"sshd:x:22:22:sshd:/dev/null:/sbin/nologin\n" +
						"deploy:x:1000:1000:deploy:/home/deploy:/bin/sh\n",
				)},
				"etc/shadow": {Data: []byte(
					"root:$6$rounds=5000$saltsalt$hashhash:19000:0:99999:7:::\n" +
						"sshd:!:19000:0:99999:7:::\n" +
						"deploy:*:19000:0:99999:7:::\n",
				)},
			},
			pkgs: []*extractor.Package{
				osPkg("musl", "1.2.5-r0"),
				osPkg("openssh-server", "10.3_p1-r1"),
			},
			wantFound: true,
			wantExtra: "openssh_version=openssh-server@10.3_p1-r1; config_source=/etc/ssh/sshd_config; borrowed_salt=$6$ (root in /etc/shadow); vulnerable_accounts=deploy[/etc/shadow]",
		},
		{
			name: "vulnerable_no_shadow_file_all_in_etc_passwd",
			fsys: fstest.MapFS{
				"lib/ld-musl-x86_64.so.1": {Data: []byte("musl")},
				"usr/sbin/sshd":           {Data: []byte("OpenSSH_10.6p1")},
				"etc/passwd": {Data: []byte(
					"root:$2b$12$abcdefghijklmnopqrstuuhash:0:0:root:/root:/bin/sh\n" +
						"git:*:1001:1001:git:/home/git:/bin/sh\n",
				)},
			},
			wantFound: true,
			wantExtra: "openssh_version=10.6p1; config_source=defaults; borrowed_salt=$2b$ (root in /etc/passwd); vulnerable_accounts=git[/etc/passwd(no-shadow)]",
		},
		{
			name: "vulnerable_partial_no_shadow_salt_in_shadow_target_in_passwd",
			fsys: fstest.MapFS{
				"usr/sbin/sshd": {Data: []byte("ld-musl-x86_64.so.1 OpenSSH_10.6p1")},
				"etc/passwd": {Data: []byte(
					"root:x:0:0:root:/root:/bin/sh\n" +
						"appuser:*:1000:1000:appuser:/app:/bin/sh\n",
				)},
				"etc/shadow": {Data: []byte(
					"root:$5$saltsalt$hashhash:19000:0:99999:7:::\n",
				)},
			},
			pkgs: []*extractor.Package{
				osPkg("musl", "1.2.5-r0"),
				osPkg("openssh-server", "10.6_p1-r0"),
			},
			wantFound: true,
			wantExtra: "openssh_version=openssh-server@10.6_p1-r0; config_source=defaults; borrowed_salt=$5$ (root in /etc/shadow); vulnerable_accounts=appuser[/etc/passwd(no-shadow)]",
		},
		{
			name: "safe_no_shadow_des_fallback_when_no_modular_hash_exists",
			fsys: fstest.MapFS{
				"usr/sbin/sshd": {Data: []byte("ld-musl-x86_64.so.1 OpenSSH_10.6p1")},
				"etc/passwd": {Data: []byte(
					"root:x:0:0:root:/root:/bin/sh\n" +
						"deploy:x:1000:1000:deploy:/home/deploy:/bin/sh\n",
				)},
				"etc/shadow": {Data: []byte(
					"root:*:19000:0:99999:7:::\n" +
						"deploy:*:19000:0:99999:7:::\n",
				)},
			},
			pkgs: []*extractor.Package{
				osPkg("musl", "1.2.5-r0"),
				osPkg("openssh-server", "10.6_p1-r0"),
			},
			wantFound: false,
		},
		{
			name: "safe_no_shadow_when_passwd_has_x_and_not_star",
			fsys: fstest.MapFS{
				"usr/sbin/sshd": {Data: []byte("ld-musl-x86_64.so.1 OpenSSH_10.6p1")},
				"etc/passwd": {Data: []byte(
					"root:$6$saltsalt$hash:0:0:root:/root:/bin/sh\n" +
						"deploy:x:1000:1000:deploy:/home/deploy:/bin/sh\n",
				)},
			},
			pkgs: []*extractor.Package{
				osPkg("musl", "1.2.5-r0"),
				osPkg("openssh-server", "10.6_p1-r0"),
			},
			wantFound: false,
		},
		{
			name: "safe_md5_1_salt_does_not_fail_under_1024_bytes",
			fsys: fstest.MapFS{
				"usr/sbin/sshd": {Data: []byte("ld-musl-x86_64.so.1 OpenSSH_10.6p1")},
				"etc/passwd": {Data: []byte(
					"root:x:0:0:root:/root:/bin/sh\n" +
						"deploy:x:1000:1000:deploy:/home/deploy:/bin/sh\n",
				)},
				"etc/shadow": {Data: []byte(
					"root:$1$md5salt$hash:19000:0:99999:7:::\n" +
						"deploy:*:19000:0:99999:7:::\n",
				)},
			},
			pkgs: []*extractor.Package{
				osPkg("musl", "1.2.5-r0"),
				osPkg("openssh-server", "10.6_p1-r0"),
			},
			wantFound: false,
		},
		{
			name: "safe_patched_upstream_version_10_6_p2",
			fsys: fstest.MapFS{
				"usr/sbin/sshd": {Data: []byte("ld-musl-x86_64.so.1 OpenSSH_10.6p2")},
				"etc/passwd": {Data: []byte(
					"root:x:0:0:root:/root:/bin/sh\n" +
						"deploy:x:1000:1000:deploy:/home/deploy:/bin/sh\n",
				)},
				"etc/shadow": {Data: []byte(
					"root:$6$saltsalt$hash:19000:0:99999:7:::\n" +
						"deploy:*:19000:0:99999:7:::\n",
				)},
			},
			pkgs: []*extractor.Package{
				osPkg("musl", "1.2.5-r0"),
				osPkg("openssh-server", "10.6_p2-r0"),
			},
			wantFound: false,
		},
		{
			name: "safe_patched_alpine_backport_10_3_p1_r2",
			fsys: fstest.MapFS{
				"usr/sbin/sshd": {Data: []byte("ld-musl-x86_64.so.1 OpenSSH_10.3p1")},
				"etc/passwd": {Data: []byte(
					"root:x:0:0:root:/root:/bin/sh\n" +
						"deploy:x:1000:1000:deploy:/home/deploy:/bin/sh\n",
				)},
				"etc/shadow": {Data: []byte(
					"root:$6$saltsalt$hash:19000:0:99999:7:::\n" +
						"deploy:*:19000:0:99999:7:::\n",
				)},
			},
			pkgs: []*extractor.Package{
				osPkg("musl", "1.2.5-r0"),
				apkPkg("openssh-server", "10.3_p1-r2"),
			},
			wantFound: false,
		},
		{
			name: "vulnerable_gentoo_revision_not_treated_as_alpine_backport",
			fsys: fstest.MapFS{
				"usr/sbin/sshd": {Data: []byte("ld-musl-x86_64.so.1 OpenSSH_9.6p1")},
				"etc/passwd": {Data: []byte(
					"root:x:0:0:root:/root:/bin/sh\n" +
						"deploy:x:1000:1000:deploy:/home/deploy:/bin/sh\n",
				)},
				"etc/shadow": {Data: []byte(
					"root:$6$saltsalt$hash:19000:0:99999:7:::\n" +
						"deploy:*:19000:0:99999:7:::\n",
				)},
			},
			pkgs: []*extractor.Package{
				osPkg("net-misc/openssh", "9.6_p1-r3"),
			},
			wantFound: true,
			wantExtra: "openssh_version=net-misc/openssh@9.6_p1-r3; config_source=defaults; borrowed_salt=$6$ (root in /etc/shadow); vulnerable_accounts=deploy[/etc/shadow]",
		},
		{
			name: "safe_patched_binary_with_compat_table_strings_before_banner",
			fsys: fstest.MapFS{
				"usr/sbin/sshd": {Data: []byte(
					"ld-musl-x86_64.so.1 OpenSSH_2.*,OpenSSH_3.0*,OpenSSH_3.1* OpenSSH_6.6.1* OpenSSH_7.4* OpenSSH_10.6p2",
				)},
				"etc/passwd": {Data: []byte(
					"root:x:0:0:root:/root:/bin/sh\n" +
						"deploy:x:1000:1000:deploy:/home/deploy:/bin/sh\n",
				)},
				"etc/shadow": {Data: []byte(
					"root:$6$saltsalt$hash:19000:0:99999:7:::\n" +
						"deploy:*:19000:0:99999:7:::\n",
				)},
			},
			wantFound: false,
		},
		{
			name: "safe_password_authentication_disabled_via_included_config",
			fsys: fstest.MapFS{
				"usr/sbin/sshd": {Data: []byte("ld-musl-x86_64.so.1 OpenSSH_10.3p1")},
				"etc/ssh/sshd_config": {Data: []byte(
					"Include /etc/ssh/sshd_config.d/*.conf\n" +
						"PasswordAuthentication yes\n",
				)},
				"etc/ssh/sshd_config.d/00-hardening.conf": {Data: []byte(
					"PasswordAuthentication no\n",
				)},
				"etc/passwd": {Data: []byte(
					"root:x:0:0:root:/root:/bin/sh\n" +
						"deploy:x:1000:1000:deploy:/home/deploy:/bin/sh\n",
				)},
				"etc/shadow": {Data: []byte(
					"root:$6$saltsalt$hash:19000:0:99999:7:::\n" +
						"deploy:*:19000:0:99999:7:::\n",
				)},
			},
			pkgs: []*extractor.Package{
				osPkg("musl", "1.2.5-r0"),
				osPkg("openssh-server", "10.3_p1-r1"),
			},
			wantFound: false,
		},
		{
			name: "safe_usepam_yes_with_openssh_server_pam",
			fsys: fstest.MapFS{
				"usr/sbin/sshd":       {Data: []byte("ld-musl-x86_64.so.1 libpam.so.0 OpenSSH_10.3p1")},
				"etc/ssh/sshd_config": {Data: []byte("UsePAM yes\n")},
				"etc/passwd": {Data: []byte(
					"root:x:0:0:root:/root:/bin/sh\n" +
						"deploy:x:1000:1000:deploy:/home/deploy:/bin/sh\n",
				)},
				"etc/shadow": {Data: []byte(
					"root:$6$saltsalt$hash:19000:0:99999:7:::\n" +
						"deploy:*:19000:0:99999:7:::\n",
				)},
			},
			pkgs: []*extractor.Package{
				osPkg("musl", "1.2.5-r0"),
				osPkg("openssh-server-pam", "10.3_p1-r1"),
			},
			wantFound: false,
		},
		{
			name: "safe_root_star_blocked_by_default_permit_root_login_prohibit_password",
			fsys: fstest.MapFS{
				"usr/sbin/sshd": {Data: []byte("ld-musl-x86_64.so.1 OpenSSH_10.3p1")},
				"etc/passwd": {Data: []byte(
					"admin:x:1000:1000:admin:/home/admin:/bin/sh\n" +
						"root:x:0:0:root:/root:/bin/sh\n",
				)},
				"etc/shadow": {Data: []byte(
					"admin:$6$saltsalt$hash:19000:0:99999:7:::\n" +
						"root:*:19000:0:99999:7:::\n",
				)},
			},
			pkgs: []*extractor.Package{
				osPkg("musl", "1.2.5-r0"),
				osPkg("openssh-server", "10.3_p1-r1"),
			},
			wantFound: false,
		},
		{
			name: "vulnerable_root_star_when_permit_root_login_yes",
			fsys: fstest.MapFS{
				"usr/sbin/sshd":       {Data: []byte("ld-musl-x86_64.so.1 OpenSSH_10.3p1")},
				"etc/ssh/sshd_config": {Data: []byte("PermitRootLogin yes\n")},
				"etc/passwd": {Data: []byte(
					"admin:x:1000:1000:admin:/home/admin:/bin/sh\n" +
						"root:x:0:0:root:/root:/bin/sh\n",
				)},
				"etc/shadow": {Data: []byte(
					"admin:$6$saltsalt$hash:19000:0:99999:7:::\n" +
						"root:*:19000:0:99999:7:::\n",
				)},
			},
			pkgs: []*extractor.Package{
				osPkg("musl", "1.2.5-r0"),
				osPkg("openssh-server", "10.3_p1-r1"),
			},
			wantFound: true,
			wantExtra: "openssh_version=openssh-server@10.3_p1-r1; config_source=/etc/ssh/sshd_config; borrowed_salt=$6$ (admin in /etc/shadow); vulnerable_accounts=root[/etc/shadow]",
		},
		{
			name: "vulnerable_non_alpine_debian_musl_packages_and_usr_local_sbin_sshd",
			fsys: fstest.MapFS{
				"usr/local/sbin/sshd": {Data: []byte("ELF-placeholder ld-musl-x86_64.so.1 OpenSSH_9.2p1")},
				"etc/ssh/sshd_config": {Data: []byte("PasswordAuthentication yes\n")},
				"etc/passwd": {Data: []byte(
					"root:x:0:0:root:/root:/bin/sh\n" +
						"targetuser:x:1000:1000:targetuser:/home/targetuser:/bin/sh\n",
				)},
				"etc/shadow": {Data: []byte(
					"root:$6$saltsalt$hashhash:19000:0:99999:7:::\n" +
						"targetuser:*:19000:0:99999:7:::\n",
				)},
			},
			pkgs: []*extractor.Package{
				osPkg("openssh-server", "1:9.2p1-2+deb12u3"),
			},
			wantFound: true,
			wantExtra: "openssh_version=openssh-server@1:9.2p1-2+deb12u3; config_source=/etc/ssh/sshd_config; borrowed_salt=$6$ (root in /etc/shadow); vulnerable_accounts=targetuser[/etc/shadow]",
		},
		{
			name: "vulnerable_void_linux_musl_with_etc_ld_musl_path_and_xbps_pkg",
			fsys: fstest.MapFS{
				"etc/ld-musl-x86_64.path": {Data: []byte("/usr/lib\n")},
				"usr/bin/sshd":            {Data: []byte("OpenSSH_9.9p1")},
				"etc/ssh/sshd_config":     {Data: []byte("PasswordAuthentication yes\n")},
				"etc/passwd": {Data: []byte(
					"donoruser:x:1000:1000:donoruser:/home/donoruser:/bin/sh\n" +
						"targetuser:x:1001:1001:targetuser:/home/targetuser:/bin/sh\n",
				)},
				"etc/shadow": {Data: []byte(
					"donoruser:$6$rounds=5000$saltsalt$hash:19000:0:99999:7:::\n" +
						"targetuser:*:19000:0:99999:7:::\n",
				)},
			},
			pkgs: []*extractor.Package{
				osPkg("openssh", "9.9p1_1"),
			},
			wantFound: true,
			wantExtra: "openssh_version=openssh@9.9p1_1; config_source=/etc/ssh/sshd_config; borrowed_salt=$6$ (donoruser in /etc/shadow); vulnerable_accounts=targetuser[/etc/shadow]",
		},
		{
			name: "vulnerable_custom_binary_no_packages_musl_detected_from_binary_bytes",
			fsys: fstest.MapFS{
				"usr/local/bin/sshd":  {Data: []byte("static-binary libc.musl-x86_64.so.1 OpenSSH_9.6p1")},
				"etc/ssh/sshd_config": {Data: []byte("PasswordAuthentication yes\n")},
				"etc/passwd": {Data: []byte(
					"donoruser:x:1000:1000:donoruser:/home/donoruser:/bin/sh\n" +
						"targetuser:x:1001:1001:targetuser:/home/targetuser:/bin/sh\n",
				)},
				"etc/shadow": {Data: []byte(
					"donoruser:$6$saltsalt$hash:19000:0:99999:7:::\n" +
						"targetuser:*:19000:0:99999:7:::\n",
				)},
			},
			wantFound: true,
			wantExtra: "openssh_version=9.6p1; config_source=/etc/ssh/sshd_config; borrowed_salt=$6$ (donoruser in /etc/shadow); vulnerable_accounts=targetuser[/etc/shadow]",
		},
		{
			name: "safe_custom_binary_with_libpam_bytes_and_usepam_yes",
			fsys: fstest.MapFS{
				"usr/sbin/sshd":       {Data: []byte("ld-musl-aarch64.so.1 libpam.so.0 OpenSSH_9.6p1")},
				"etc/ssh/sshd_config": {Data: []byte("UsePAM yes\nPasswordAuthentication yes\n")},
				"etc/passwd": {Data: []byte(
					"donoruser:x:1000:1000:donoruser:/home/donoruser:/bin/sh\n" +
						"targetuser:x:1001:1001:targetuser:/home/targetuser:/bin/sh\n",
				)},
				"etc/shadow": {Data: []byte(
					"donoruser:$6$saltsalt$hash:19000:0:99999:7:::\n" +
						"targetuser:*:19000:0:99999:7:::\n",
				)},
			},
			wantFound: false,
		},
		{
			name: "safe_glibc_elf_interp_even_when_musl_loader_exists_on_disk",
			fsys: fstest.MapFS{
				"lib/ld-musl-x86_64.so.1": {Data: []byte("musl")},
				"usr/sbin/sshd":           {Data: minimalELFWithInterp("/lib64/ld-linux-x86-64.so.2", "OpenSSH_9.6p1")},
				"etc/ssh/sshd_config":     {Data: []byte("PasswordAuthentication yes\n")},
				"etc/passwd": {Data: []byte(
					"donoruser:x:1000:1000:donoruser:/home/donoruser:/bin/sh\n" +
						"targetuser:x:1001:1001:targetuser:/home/targetuser:/bin/sh\n",
				)},
				"etc/shadow": {Data: []byte(
					"donoruser:$6$saltsalt$hash:19000:0:99999:7:::\n" +
						"targetuser:*:19000:0:99999:7:::\n",
				)},
			},
			wantFound: false,
		},
		{
			name: "safe_system_accounts_with_nologin_or_bin_false_ignored",
			fsys: fstest.MapFS{
				"lib/ld-musl-x86_64.so.1": {Data: []byte("musl")},
				"usr/sbin/sshd":           {Data: []byte("ld-musl-x86_64.so.1 OpenSSH_10.6p1")},
				"etc/ssh/sshd_config":     {Data: []byte("PasswordAuthentication yes\nPermitRootLogin yes\n")},
				"etc/passwd": {Data: []byte(
					"root:x:0:0:root:/root:/bin/ash\n" +
						"daemon:*:1:1:daemon:/var:/bin/false\n" +
						"nobody:*:65534:65534:nobody:/var:/sbin/nologin\n" +
						"sshd:x:22:22:sshd:/var/empty:/bin/false\n" +
						"donoruser:x:1000:1000:donoruser:/home/donoruser:/bin/ash\n" +
						"targetuser:x:1001:1001:targetuser:/home/targetuser:/bin/ash\n",
				)},
				"etc/shadow": {Data: []byte(
					"root:!:19000:0:99999:7:::\n" +
						"daemon:*:19000:0:99999:7:::\n" +
						"nobody:*:19000:0:99999:7:::\n" +
						"sshd:*:19000:0:99999:7:::\n" +
						"donoruser:$6$saltsalt$hash:19000:0:99999:7:::\n" +
						"targetuser:!:19000:0:99999:7:::\n",
				)},
			},
			wantFound: false,
		},
		{
			name: "safe_deny_users_wildcard_excludes_target",
			fsys: fstest.MapFS{
				"usr/sbin/sshd":       {Data: []byte("ld-musl-x86_64.so.1 OpenSSH_10.6p1")},
				"etc/ssh/sshd_config": {Data: []byte("DenyUsers svc-*\n")},
				"etc/passwd": {Data: []byte(
					"donoruser:$6$saltsalt$hash:1000:1000:donoruser:/home/donoruser:/bin/sh\n" +
						"svc-build:*:1001:1001:svc:/home/svc:/bin/sh\n",
				)},
			},
			wantFound: false,
		},
		{
			name: "vulnerable_deny_users_with_host_part_does_not_exclude_target",
			fsys: fstest.MapFS{
				"usr/sbin/sshd":       {Data: []byte("ld-musl-x86_64.so.1 OpenSSH_10.6p1")},
				"etc/ssh/sshd_config": {Data: []byte("DenyUsers svc-build@10.0.0.1\n")},
				"etc/passwd": {Data: []byte(
					"donoruser:$6$saltsalt$hash:1000:1000:donoruser:/home/donoruser:/bin/sh\n" +
						"svc-build:*:1001:1001:svc:/home/svc:/bin/sh\n",
				)},
			},
			wantFound: true,
			wantExtra: "openssh_version=10.6p1; config_source=/etc/ssh/sshd_config; borrowed_salt=$6$ (donoruser in /etc/passwd); vulnerable_accounts=svc-build[/etc/passwd(no-shadow)]",
		},
		{
			name: "vulnerable_allow_users_user_at_host_and_wildcard",
			fsys: fstest.MapFS{
				"usr/sbin/sshd":       {Data: []byte("ld-musl-x86_64.so.1 OpenSSH_10.6p1")},
				"etc/ssh/sshd_config": {Data: []byte("AllowUsers deploy@10.* ci-?\n")},
				"etc/passwd": {Data: []byte(
					"donoruser:$6$saltsalt$hash:1000:1000:donoruser:/home/donoruser:/bin/sh\n" +
						"deploy:*:1001:1001:deploy:/home/deploy:/bin/sh\n" +
						"ci-1:*:1002:1002:ci:/home/ci:/bin/sh\n" +
						"other:*:1003:1003:other:/home/other:/bin/sh\n",
				)},
			},
			wantFound: true,
			wantExtra: "openssh_version=10.6p1; config_source=/etc/ssh/sshd_config; borrowed_salt=$6$ (donoruser in /etc/passwd); " +
				"vulnerable_accounts=deploy[/etc/passwd(no-shadow)],ci-1[/etc/passwd(no-shadow)]",
		},
		{
			name: "vulnerable_allow_groups_matches_primary_and_supplementary_groups",
			fsys: fstest.MapFS{
				"usr/sbin/sshd":       {Data: []byte("ld-musl-x86_64.so.1 OpenSSH_10.6p1")},
				"etc/ssh/sshd_config": {Data: []byte("AllowGroups ssh-*\n")},
				"etc/group": {Data: []byte(
					"users:x:100:\n" +
						"ssh-users:x:200:\n" +
						"ssh-ops:x:201:opsuser\n",
				)},
				"etc/passwd": {Data: []byte(
					"donoruser:$6$saltsalt$hash:1000:100:donoruser:/home/donoruser:/bin/sh\n" +
						"primary:*:1001:200:primary:/home/primary:/bin/sh\n" +
						"opsuser:*:1002:100:ops:/home/ops:/bin/sh\n" +
						"outsider:*:1003:100:outsider:/home/outsider:/bin/sh\n",
				)},
			},
			wantFound: true,
			wantExtra: "openssh_version=10.6p1; config_source=/etc/ssh/sshd_config; borrowed_salt=$6$ (donoruser in /etc/passwd); " +
				"vulnerable_accounts=primary[/etc/passwd(no-shadow)],opsuser[/etc/passwd(no-shadow)]",
		},
		{
			name: "safe_deny_groups_excludes_target",
			fsys: fstest.MapFS{
				"usr/sbin/sshd":       {Data: []byte("ld-musl-x86_64.so.1 OpenSSH_10.6p1")},
				"etc/ssh/sshd_config": {Data: []byte("DenyGroups nossh\n")},
				"etc/group":           {Data: []byte("users:x:100:\nnossh:x:300:target\n")},
				"etc/passwd": {Data: []byte(
					"donoruser:$6$saltsalt$hash:1000:100:donoruser:/home/donoruser:/bin/sh\n" +
						"target:*:1001:100:target:/home/target:/bin/sh\n",
				)},
			},
			wantFound: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			det := &Detector{
				cmdRunner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
					t.Fatalf("cmdRunner must not be invoked during virtual container scan (called %s %v)", name, args)
					return nil, nil
				},
			}
			// Simulate Container Scanning (Path == "" => scanRoot.IsVirtual() == true).
			scanRoot := &scalibrfs.ScanRoot{FS: tc.fsys, Path: ""}
			px := makePkgIndex(t, tc.pkgs...)

			got, err := det.Scan(context.Background(), scanRoot, px)
			if err != nil {
				t.Fatalf("Scan() returned unexpected error: %v", err)
			}
			if !tc.wantFound {
				if len(got.GenericFindings) > 0 {
					t.Fatalf("Scan() = %+v, want no findings", got)
				}
				return
			}
			want := findingForTarget(&inventory.GenericFindingTargetDetails{Extra: tc.wantExtra})
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Scan() finding diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLiveSystemScan(t *testing.T) {
	baseFS := fstest.MapFS{
		"lib/ld-musl-x86_64.so.1": {Data: []byte("musl")},
		"usr/sbin/sshd":           {Data: []byte("custom-binary-without-rodata-banner")},
		"etc/passwd": {Data: []byte(
			"root:x:0:0:root:/root:/bin/sh\n" +
				"svc:*:1000:1000:svc:/var/empty:/bin/sh\n",
		)},
		"etc/shadow": {Data: []byte(
			"root:$6$saltsalt$hash:19000:0:99999:7:::\n" +
				"svc:*:19000:0:99999:7:::\n",
		)},
	}

	t.Run("live_sshd_commands_detect_vulnerable_host", func(t *testing.T) {
		det := &Detector{
			cmdRunner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if len(args) == 1 && args[0] == "-V" {
					return []byte("OpenSSH_10.5p1, OpenSSL 3.3.2\n"), nil
				}
				if len(args) == 1 && args[0] == "-T" {
					return []byte("passwordauthentication yes\nusepam no\npermitrootlogin prohibit-password\n"), nil
				}
				return nil, errors.New("unexpected command")
			},
		}
		// Simulate live-host scan (Path == "/" => !scanRoot.IsVirtual()).
		scanRoot := &scalibrfs.ScanRoot{FS: baseFS, Path: "/"}
		px := makePkgIndex(t)

		got, err := det.Scan(context.Background(), scanRoot, px)
		if err != nil {
			t.Fatalf("Scan() returned unexpected error: %v", err)
		}
		want := findingForTarget(&inventory.GenericFindingTargetDetails{
			Extra: "openssh_version=10.5p1; config_source=sshd -T; borrowed_salt=$6$ (root in /etc/shadow); vulnerable_accounts=svc[/etc/shadow]",
		})
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("Scan() finding diff (-want +got):\n%s", diff)
		}
	})

	t.Run("live_sshd_T_reports_passwordauthentication_no", func(t *testing.T) {
		det := &Detector{
			cmdRunner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if len(args) == 1 && args[0] == "-V" {
					return []byte("OpenSSH_10.5p1\n"), nil
				}
				if len(args) == 1 && args[0] == "-T" {
					return []byte("passwordauthentication no\nusepam no\n"), nil
				}
				return nil, errors.New("unexpected command")
			},
		}
		scanRoot := &scalibrfs.ScanRoot{FS: baseFS, Path: "/"}
		px := makePkgIndex(t)

		got, err := det.Scan(context.Background(), scanRoot, px)
		if err != nil {
			t.Fatalf("Scan() returned unexpected error: %v", err)
		}
		if len(got.GenericFindings) != 0 {
			t.Errorf("Scan() = %+v, want no findings when live sshd -T disables PasswordAuthentication", got)
		}
	})

	t.Run("unreadable_shadow_returns_error_instead_of_no_shadow_fallback", func(t *testing.T) {
		det := &Detector{
			cmdRunner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if len(args) == 1 && args[0] == "-V" {
					return []byte("OpenSSH_10.5p1\n"), nil
				}
				// Non-root: sshd -T fails, so the detector falls back to static parsing.
				return nil, errors.New("sshd: no hostkeys available -- exiting")
			},
		}
		fsys := fstest.MapFS{
			"lib/ld-musl-x86_64.so.1": {Data: []byte("musl")},
			"usr/sbin/sshd":           {Data: []byte("custom-binary-without-rodata-banner")},
			"etc/passwd": {Data: []byte(
				"root:$6$saltsalt$hash:0:0:root:/root:/bin/sh\n" +
					"svc:*:1000:1000:svc:/var/empty:/bin/sh\n",
			)},
			"etc/shadow": {Data: []byte("root:$6$saltsalt$hash:19000:0:99999:7:::\nsvc:$6$real$hash:19000:0:99999:7:::\n")},
		}
		scanRoot := &scalibrfs.ScanRoot{
			FS:   errOnOpenFS{MapFS: fsys, failPath: "etc/shadow", err: fs.ErrPermission},
			Path: "/",
		}

		got, err := det.Scan(context.Background(), scanRoot, makePkgIndex(t))
		if !errors.Is(err, fs.ErrPermission) {
			t.Errorf("Scan() error = %v, want %v", err, fs.ErrPermission)
		}
		if len(got.GenericFindings) != 0 {
			t.Errorf("Scan() = %+v, want no findings when /etc/shadow is unreadable", got)
		}
	})
}

func TestIsVulnerableOpenSSHVersion(t *testing.T) {
	tests := []struct {
		verStr string
		alpine bool
		want   bool
	}{
		{"OpenSSH_8.8p1", false, true},
		{"8.8p1", false, true},
		{"8.8_p1-r1", true, true},
		{"1:9.2p1-2+deb12u3", false, true},
		{"9.9p1_1", false, true},
		{"10.6p1", false, true},
		{"10.6_p1-r0", true, true},
		{"10.6p2", false, false},
		{"10.6_p2-r0", true, false},
		{"10.6_p2-r0", false, false},
		{"1:10.6p2-1", false, false},
		{"10.7p1", false, false},
		{"11.0p1", false, false},
		{"10.3_p1-r1", true, true},
		{"10.3_p1-r2", true, false},
		{"10.3_p1-r3", true, false},
		{"9.9_p2-r0", true, true},
		{"9.9_p2-r1", true, false},
		{"9.9_p1-r2", true, true},
		{"9.9_p1-r3", true, false},
		{"9.7_p1-r5", true, true},
		{"9.7_p1-r6", true, false},
		{"9.6_p1-r2", true, true},
		{"9.6_p1-r3", true, false},
		{"9.3_p2-r3", true, true},
		{"9.3_p2-r4", true, false},
		{"9.1_p1-r6", true, true},
		{"9.1_p1-r7", true, false},
		{"9.0_p1-r5", true, true},
		{"9.0_p1-r6", true, false},
		// Non-Alpine -r<N> revisions (e.g. Gentoo) must not use the Alpine backport table.
		{"9.6_p1-r3", false, true},
		{"10.3_p1-r2", false, true},
		{"invalid", false, false},
	}
	for _, tc := range tests {
		if got := isVulnerableOpenSSHVersion(tc.verStr, tc.alpine); got != tc.want {
			t.Errorf("isVulnerableOpenSSHVersion(%q, %v) = %v, want %v", tc.verStr, tc.alpine, got, tc.want)
		}
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		s, pattern string
		want       bool
	}{
		{"deploy", "deploy", true},
		{"deploy", "Deploy", false},
		{"deploy", "dep*", true},
		{"deploy", "*", true},
		{"deploy", "d?ploy", true},
		{"deploy", "d?loy", false},
		{"deploy", "*loy", true},
		{"deploy", "*x*", false},
		{"", "*", true},
		{"", "?", false},
	}
	for _, tc := range tests {
		if got := matchPattern(tc.s, tc.pattern); got != tc.want {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", tc.s, tc.pattern, got, tc.want)
		}
	}
}
