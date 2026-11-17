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

package scalibr_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"archive/tar"

	scalibr "github.com/google/osv-scalibr"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/archive"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/misc/gitrepo"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/veles/secrets/privatekey"
)

func mustWriteFile(tb testing.TB, root, relPath string, data []byte) {
	tb.Helper()
	full := filepath.Join(root, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		tb.Fatalf("MkdirAll(%q): %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, data, 0o644); err != nil {
		tb.Fatalf("WriteFile(%q): %v", full, err)
	}
}

func mustSymlink(tb testing.TB, root, target, relPath string) {
	tb.Helper()
	full := filepath.Join(root, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		tb.Fatalf("MkdirAll(%q): %v", filepath.Dir(full), err)
	}
	if err := os.Symlink(target, full); err != nil {
		tb.Fatalf("Symlink(%q -> %q): %v", full, target, err)
	}
}

func generateTestECPrivateKeyPEM(tb testing.TB) []byte {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		tb.Fatalf("x509.MarshalECPrivateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})
}

func mustNewExtractor(tb testing.TB, ctor func(*cpb.PluginConfig) (filesystem.Extractor, error)) plugin.Plugin {
	tb.Helper()
	p, err := ctor(&cpb.PluginConfig{})
	if err != nil {
		tb.Fatalf("extractor constructor failed: %v", err)
	}
	return p
}

func assertScanSucceeded(tb testing.TB, sr *scalibr.ScanResult) {
	tb.Helper()
	if sr.Status.Status != plugin.ScanStatusSucceeded {
		tb.Fatalf("Scan() status = %v, want SUCCEEDED", sr.Status)
	}
	for _, st := range sr.PluginStatus {
		if st.Status.Status != plugin.ScanStatusSucceeded {
			tb.Errorf("PluginStatus[%q] = %v, want SUCCEEDED", st.Name, st.Status)
		}
	}
}

func packageSet(sr *scalibr.ScanResult) map[string]bool {
	got := make(map[string]bool, len(sr.Inventory.Packages))
	for _, p := range sr.Inventory.Packages {
		got[p.Name+"@"+p.Version] = true
	}
	return got
}

func TestScan_ConfinedFS_MultiPluginEndToEnd(t *testing.T) {
	parent := t.TempDir()
	outside := filepath.Join(parent, "outside")
	scanRoot := filepath.Join(parent, "rootfs")
	if err := os.MkdirAll(scanRoot, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", scanRoot, err)
	}

	pemKey := generateTestECPrivateKeyPEM(t)

	// OS packages (Debian dpkg + Alpine apk). On non-Windows, place the Debian
	// os-release file at a non-fallback path ("opt/distro/os-release") referenced
	// by an intra-guest absolute symlink ("etc/os-release -> /opt/distro/os-release")
	// so curl's Debian:12 ecosystem directly proves intra-root absolute symlink
	// resolution rather than osrelease.GetOSRelease's usr/lib/os-release fallback.
	if runtime.GOOS == "windows" {
		mustWriteFile(t, scanRoot, "usr/lib/os-release", []byte("ID=debian\nVERSION_ID=\"12\"\n"))
	} else {
		mustWriteFile(t, scanRoot, "opt/distro/os-release", []byte("ID=debian\nVERSION_ID=\"12\"\n"))
	}
	mustWriteFile(t, scanRoot, "var/lib/dpkg/status", []byte(
		"Package: curl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 8.5.0-2\n\n",
	))
	mustWriteFile(t, scanRoot, "lib/apk/db/installed", []byte(
		"P:musl\nV:1.2.4-r2\nA:x86_64\n\n",
	))

	// Language packages (JS, Go, Python) + oversized file (> 256 KiB MaxFileSize)
	// to verify lazyFileAPI.Stat.
	mustWriteFile(t, scanRoot, "srv/web/app/package.json", []byte(`{"name":"web-app","version":"1.2.3"}`))
	oversized := `{"name":"oversized-app","version":"9.9.9","pad":"` + strings.Repeat("a", 300*1024) + `"}`
	mustWriteFile(t, scanRoot, "srv/web/oversized/package.json", []byte(oversized))
	mustWriteFile(t, scanRoot, "srv/backend/go.mod", []byte("module example.com/backend\n\ngo 1.22\n\nrequire golang.org/x/text v0.14.0\n"))
	mustWriteFile(t, scanRoot, "usr/lib/python3/dist-packages/requests-2.31.0.dist-info/METADATA", []byte(
		"Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n",
	))

	// Deeply nested directory (depth > 32) to exercise deep traversal within FD limits.
	deepPkgPath := "deep/" + strings.Repeat("d/", 40) + "package.json"
	mustWriteFile(t, scanRoot, deepPkgPath, []byte(`{"name":"deep-pkg","version":"0.0.1"}`))

	// Directory extractor fixture (misc/gitrepo).
	mustWriteFile(t, scanRoot, "opt/repo/.git/config", []byte("[remote \"origin\"]\n\turl = https://github.com/example/demo.git\n"))

	// Secret fixture (Veles privatekey detector).
	mustWriteFile(t, scanRoot, "etc/ssl/app.pem", pemKey)

	// Directory skip filters: DirsToSkip, SkipDirRegex, and UseGitignore.
	mustWriteFile(t, scanRoot, "skip-by-name/package.json", []byte(`{"name":"skipped-dir-pkg","version":"1.0.0"}`))
	mustWriteFile(t, scanRoot, "skip-by-regex/package.json", []byte(`{"name":"skipped-regex-pkg","version":"1.0.0"}`))
	mustWriteFile(t, scanRoot, "srv/.gitignore", []byte("ignored/\n"))
	mustWriteFile(t, scanRoot, "srv/ignored/package.json", []byte(`{"name":"gitignored-pkg","version":"1.0.0"}`))

	// Symlink confinement, intra-guest relative/absolute symlinks, and cyclic
	// symlinks on non-Windows. Created before the default ReadSymlinks: false
	// scan so both symlink modes are verified against the same tree.
	if runtime.GOOS != "windows" {
		mustSymlink(t, scanRoot, "/opt/distro/os-release", "etc/os-release")
		mustSymlink(t, scanRoot, "../../srv/web/app/package.json", "links/rel/package.json")
		mustSymlink(t, scanRoot, "/srv/web/app/package.json", "links/abs/package.json")

		// Cyclic relative, intra-root absolute, and directory self-symlinks.
		mustSymlink(t, scanRoot, "../b/package.json", "links/cycle/a/package.json")
		mustSymlink(t, scanRoot, "../a/package.json", "links/cycle/b/package.json")
		mustSymlink(t, scanRoot, "/links/cycle/abs_b/package.json", "links/cycle/abs_a/package.json")
		mustSymlink(t, scanRoot, "/links/cycle/abs_a/package.json", "links/cycle/abs_b/package.json")
		mustSymlink(t, scanRoot, "..", "links/cycle/self")

		// Host files outside scanRoot that escaping symlinks attempt to read.
		mustWriteFile(t, outside, "package.json", []byte(`{"name":"escaped-file-pkg","version":"6.6.6"}`))
		mustWriteFile(t, outside, "dir/package.json", []byte(`{"name":"escaped-dir-pkg","version":"6.6.6"}`))
		mustWriteFile(t, outside, "host.pem", pemKey)

		mustSymlink(t, scanRoot, "../../outside/package.json", "escape/package.json")
		mustSymlink(t, scanRoot, filepath.Join(outside, "package.json"), "escape/abs/package.json")
		mustSymlink(t, scanRoot, filepath.Join(outside, "host.pem"), "escape/host.pem")
		mustSymlink(t, scanRoot, filepath.Join(outside, "dir"), "escape/outside-dir")
	}

	plugins := []plugin.Plugin{
		mustNewExtractor(t, dpkg.New),
		mustNewExtractor(t, apk.New),
		mustNewExtractor(t, packagejson.New),
		mustNewExtractor(t, gomod.New),
		mustNewExtractor(t, wheelegg.New),
		mustNewExtractor(t, gitrepo.New),
		fromVelesDetector(t, privatekey.NewDetector(), "secrets/privatekey", 0),
	}

	cfg := &scalibr.ScanConfig{
		ScanRoots:    scalibrfs.ConfinedScanRoots(scanRoot),
		Plugins:      plugins,
		Capabilities: &plugin.Capabilities{DirectFS: true},
		DirsToSkip:   []string{filepath.Join(scanRoot, "skip-by-name")},
		SkipDirRegex: regexp.MustCompile(`^skip-by-regex$`),
		UseGitignore: true,
		MaxFileSize:  256 * 1024,
	}

	sr := scalibr.New().Scan(t.Context(), cfg)
	assertScanSucceeded(t, sr)

	pkgs := packageSet(sr)
	wantPkgs := []string{
		"curl@8.5.0-2",
		"musl@1.2.4-r2",
		"web-app@1.2.3",
		"golang.org/x/text@0.14.0",
		"requests@2.31.0",
		"deep-pkg@0.0.1",
		"demo@",
	}
	for _, want := range wantPkgs {
		if !pkgs[want] {
			t.Errorf("Scan() packages = %v, want %q", pkgs, want)
		}
	}

	// Verify dpkg resolved etc/os-release -> /opt/distro/os-release inside scanRoot
	// and populated Debian:12 ecosystem metadata, while ReadSymlinks: false only
	// extracted the real srv/web/app/package.json (skipping links/{rel,abs}).
	var curlEco string
	var webAppLocs []string
	for _, p := range sr.Inventory.Packages {
		if p.Name == "curl" {
			curlEco = p.Ecosystem().String()
		}
		if p.Name == "web-app" {
			webAppLocs = append(webAppLocs, p.Location.PathOrEmpty())
		}
	}
	if curlEco != "Debian:12" {
		t.Errorf("curl Ecosystem() = %q, want %q", curlEco, "Debian:12")
	}
	if !slices.Equal(webAppLocs, []string{"srv/web/app/package.json"}) {
		t.Errorf("ReadSymlinks=false web-app locations = %v, want [srv/web/app/package.json]", webAppLocs)
	}

	forbiddenPkgs := []string{
		"oversized-app@9.9.9",
		"skipped-dir-pkg@1.0.0",
		"skipped-regex-pkg@1.0.0",
		"gitignored-pkg@1.0.0",
		"escaped-file-pkg@6.6.6",
		"escaped-dir-pkg@6.6.6",
	}
	for _, bad := range forbiddenPkgs {
		if pkgs[bad] {
			t.Errorf("Scan() extracted forbidden package %q", bad)
		}
	}

	// Verify Veles secret extraction found etc/ssl/app.pem and never escaped to outside/host.pem.
	var secretPaths []string
	for _, s := range sr.Inventory.Secrets {
		secretPaths = append(secretPaths, s.Location.PathOrEmpty())
	}
	if !slices.Equal(secretPaths, []string{"etc/ssl/app.pem"}) {
		t.Errorf("Scan() secret locations = %v, want [etc/ssl/app.pem]", secretPaths)
	}

	// Also verify ReadSymlinks: true actively blocks escaping symlinks and
	// survives symlink cycles while extracting valid intra-root relative and
	// absolute symlinks.
	if runtime.GOOS != "windows" {
		t.Run("read_symlinks_confinement", func(t *testing.T) {
			symCfg := &scalibr.ScanConfig{
				ScanRoots: scalibrfs.ConfinedScanRoots(scanRoot),
				Plugins: []plugin.Plugin{
					mustNewExtractor(t, packagejson.New),
					fromVelesDetector(t, privatekey.NewDetector(), "secrets/privatekey", 0),
				},
				ReadSymlinks: true,
			}
			symSR := scalibr.New().Scan(t.Context(), symCfg)
			if symSR.Status.Status != plugin.ScanStatusSucceeded {
				t.Fatalf("ReadSymlinks Scan() status = %v, want SUCCEEDED", symSR.Status)
			}
			symPkgs := packageSet(symSR)
			for _, bad := range []string{"escaped-file-pkg@6.6.6", "escaped-dir-pkg@6.6.6"} {
				if symPkgs[bad] {
					t.Errorf("ReadSymlinks scan extracted escaped package %q", bad)
				}
			}
			// Verify intra-root symlink targets were extracted alongside the real package.json.
			var foundLocations []string
			for _, p := range symSR.Inventory.Packages {
				if p.Name == "web-app" {
					foundLocations = append(foundLocations, p.Location.PathOrEmpty())
				}
			}
			slices.Sort(foundLocations)
			wantLocations := []string{"links/abs/package.json", "links/rel/package.json", "srv/web/app/package.json"}
			if !slices.Equal(foundLocations, wantLocations) {
				t.Errorf("Scan() web-app locations = %v, want %v", foundLocations, wantLocations)
			}
			var symSecretPaths []string
			for _, s := range symSR.Inventory.Secrets {
				symSecretPaths = append(symSecretPaths, s.Location.PathOrEmpty())
			}
			if !slices.Equal(symSecretPaths, []string{"etc/ssl/app.pem"}) {
				t.Errorf("ReadSymlinks Scan() secret locations = %v, want [etc/ssl/app.pem]", symSecretPaths)
			}
		})
	}
}

func TestScan_RealFS_MultiPluginEndToEnd(t *testing.T) {
	parent := t.TempDir()
	outside := filepath.Join(parent, "outside")
	scanRoot := filepath.Join(parent, "hostroot")
	if err := os.MkdirAll(scanRoot, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", scanRoot, err)
	}

	pemKey := generateTestECPrivateKeyPEM(t)

	mustWriteFile(t, scanRoot, "usr/lib/os-release", []byte("ID=debian\nVERSION_ID=\"12\"\n"))
	mustWriteFile(t, scanRoot, "var/lib/dpkg/status", []byte(
		"Package: curl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 8.5.0-2\n\n",
	))
	mustWriteFile(t, scanRoot, "lib/apk/db/installed", []byte(
		"P:musl\nV:1.2.4-r2\nA:x86_64\n\n",
	))

	mustWriteFile(t, scanRoot, "srv/web/app/package.json", []byte(`{"name":"web-app","version":"1.2.3"}`))
	oversized := `{"name":"oversized-app","version":"9.9.9","pad":"` + strings.Repeat("a", 300*1024) + `"}`
	mustWriteFile(t, scanRoot, "srv/web/oversized/package.json", []byte(oversized))
	mustWriteFile(t, scanRoot, "srv/backend/go.mod", []byte("module example.com/backend\n\ngo 1.22\n\nrequire golang.org/x/text v0.14.0\n"))
	mustWriteFile(t, scanRoot, "usr/lib/python3/dist-packages/requests-2.31.0.dist-info/METADATA", []byte(
		"Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n",
	))
	mustWriteFile(t, scanRoot, "opt/repo/.git/config", []byte("[remote \"origin\"]\n\turl = https://github.com/example/demo.git\n"))
	mustWriteFile(t, scanRoot, "etc/ssl/app.pem", pemKey)

	if runtime.GOOS != "windows" {
		mustWriteFile(t, outside, "package.json", []byte(`{"name":"host-linked-pkg","version":"2.0.0"}`))
		mustSymlink(t, scanRoot, filepath.Join(outside, "package.json"), "links/host/package.json")
	}

	plugins := []plugin.Plugin{
		mustNewExtractor(t, dpkg.New),
		mustNewExtractor(t, apk.New),
		mustNewExtractor(t, packagejson.New),
		mustNewExtractor(t, gomod.New),
		mustNewExtractor(t, wheelegg.New),
		mustNewExtractor(t, gitrepo.New),
		fromVelesDetector(t, privatekey.NewDetector(), "secrets/privatekey", 0),
	}

	cfg := &scalibr.ScanConfig{
		ScanRoots:    scalibrfs.RealFSScanRoots(scanRoot),
		Plugins:      plugins,
		Capabilities: &plugin.Capabilities{DirectFS: true},
		MaxFileSize:  256 * 1024,
	}

	sr := scalibr.New().Scan(t.Context(), cfg)
	assertScanSucceeded(t, sr)

	pkgs := packageSet(sr)
	for _, want := range []string{
		"curl@8.5.0-2",
		"musl@1.2.4-r2",
		"web-app@1.2.3",
		"golang.org/x/text@0.14.0",
		"requests@2.31.0",
		"demo@",
	} {
		if !pkgs[want] {
			t.Errorf("Scan() packages = %v, want %q", pkgs, want)
		}
	}
	for _, bad := range []string{"oversized-app@9.9.9", "host-linked-pkg@2.0.0"} {
		if pkgs[bad] {
			t.Errorf("Scan() extracted skipped package %q", bad)
		}
	}

	var secretPaths []string
	for _, s := range sr.Inventory.Secrets {
		secretPaths = append(secretPaths, s.Location.PathOrEmpty())
	}
	if !slices.Equal(secretPaths, []string{"etc/ssl/app.pem"}) {
		t.Errorf("Scan() secret locations = %v, want [etc/ssl/app.pem]", secretPaths)
	}

	// Trusted host scans (RealFSScanRoots) allow following valid host-to-host
	// symlinks when ReadSymlinks is explicitly enabled.
	if runtime.GOOS != "windows" {
		t.Run("read_symlinks_follows_host_targets", func(t *testing.T) {
			symCfg := &scalibr.ScanConfig{
				ScanRoots: scalibrfs.RealFSScanRoots(scanRoot),
				Plugins: []plugin.Plugin{
					mustNewExtractor(t, packagejson.New),
				},
				ReadSymlinks: true,
			}
			symSR := scalibr.New().Scan(t.Context(), symCfg)
			assertScanSucceeded(t, symSR)

			var hostLocations []string
			for _, p := range symSR.Inventory.Packages {
				if p.Name == "host-linked-pkg" {
					hostLocations = append(hostLocations, p.Location.PathOrEmpty())
				}
			}
			if !slices.Equal(hostLocations, []string{"links/host/package.json"}) {
				t.Errorf("ReadSymlinks host-linked-pkg locations = %v, want [links/host/package.json]", hostLocations)
			}
		})
	}
}

func TestScan_EmbeddedFS_ArchiveEndToEnd(t *testing.T) {
	scanRoot := t.TempDir()
	pemKey := generateTestECPrivateKeyPEM(t)

	// Embedded .tar.gz archive containing nested OS + language packages and a secret.
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	tw := tar.NewWriter(gw)
	for _, entry := range []struct {
		name    string
		content []byte
	}{
		{name: "var/lib/dpkg/status", content: []byte("Package: archive-dpkg\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.1.0\n\n")},
		{name: "srv/nested/deep/package.json", content: []byte(`{"name":"archive-npm","version":"4.2.0"}`)},
		{name: "keys/archive.pem", content: pemKey},
	} {
		hdr := &tar.Header{
			Name:     entry.name,
			Mode:     0o644,
			Typeflag: tar.TypeReg,
			Size:     int64(len(entry.content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%q): %v", entry.name, err)
		}
		if _, err := tw.Write(entry.content); err != nil {
			t.Fatalf("Write(%q): %v", entry.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	mustWriteFile(t, scanRoot, "archives/bundle.tar.gz", gzBuf.Bytes())

	cfg := &scalibr.ScanConfig{
		ScanRoots: scalibrfs.RealFSScanRoots(scanRoot),
		Plugins: []plugin.Plugin{
			mustNewExtractor(t, archive.New),
			mustNewExtractor(t, dpkg.New),
			mustNewExtractor(t, packagejson.New),
			fromVelesDetector(t, privatekey.NewDetector(), "secrets/privatekey", 0),
		},
	}

	sr := scalibr.New().Scan(t.Context(), cfg)
	assertScanSucceeded(t, sr)

	// Verify the embedded archive filesystem was discovered, traversed, and cleaned up.
	var sawArchive bool
	var efsPaths []string
	for _, efs := range sr.Inventory.EmbeddedFSs {
		efsPaths = append(efsPaths, efs.Path)
		if strings.HasPrefix(efs.Path, "archives/bundle.tar.gz") {
			sawArchive = true
			if len(efs.TempPaths) == 0 {
				t.Errorf("EmbeddedFS(%q) TempPaths = empty, want >= 1 temp path", efs.Path)
			}
		}
		for _, tmpPath := range efs.TempPaths {
			if _, err := os.Stat(tmpPath); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("EmbeddedFS temp path %q still exists after Scan(): %v", tmpPath, err)
			}
		}
	}
	if !sawArchive {
		t.Errorf("Scan() EmbeddedFSs = %v, want entry with prefix %q", efsPaths, "archives/bundle.tar.gz")
	}

	pkgs := packageSet(sr)
	for _, want := range []string{"archive-dpkg@3.1.0", "archive-npm@4.2.0"} {
		if !pkgs[want] {
			t.Errorf("Scan() embedded archive packages = %v, want %q", pkgs, want)
		}
	}

	var secretPaths []string
	for _, s := range sr.Inventory.Secrets {
		secretPaths = append(secretPaths, s.Location.PathOrEmpty())
	}
	if len(secretPaths) != 1 || !strings.HasSuffix(secretPaths[0], "keys/archive.pem") {
		t.Errorf("Scan() secret locations = %v, want 1 secret ending in keys/archive.pem", secretPaths)
	}
}

// execStatExtractor exercises lazyFileAPI.Stat() during FileRequired (similar to
// executable/size-checking extractors).
type execStatExtractor struct{}

func (execStatExtractor) Name() string { return "test/exec-stat" }
func (execStatExtractor) Version() int { return 0 }
func (execStatExtractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}
func (execStatExtractor) FileRequired(api filesystem.FileAPI) bool {
	if strings.HasSuffix(api.Path(), ".bin") {
		_, _ = api.Stat()
	}
	return false
}
func (execStatExtractor) Extract(_ context.Context, _ *filesystem.ScanInput) (inventory.Inventory, error) {
	return inventory.Inventory{}, nil
}

func createDeepBenchmarkTree(b *testing.B) string {
	b.Helper()
	// depth=7, fanout=2 -> 255 directories; 20 files/dir -> 5,100 files.
	const (
		depth       = 7
		fanout      = 2
		filesPerDir = 20
	)
	root := b.TempDir()
	var build func(dir string, d int)
	build = func(dir string, d int) {
		for i := range filesPerDir {
			ext := ".txt"
			if i%5 == 0 {
				ext = ".bin"
			}
			name := filepath.Join(dir, "file_"+strconv.Itoa(i)+ext)
			if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
				b.Fatalf("WriteFile(%q): %v", name, err)
			}
		}
		if d == 0 {
			return
		}
		for i := range fanout {
			sub := filepath.Join(dir, "dir_"+strconv.Itoa(i))
			if err := os.Mkdir(sub, 0o755); err != nil {
				b.Fatalf("Mkdir(%q): %v", sub, err)
			}
			build(sub, d-1)
		}
	}
	build(root, depth)
	// Seed a few real manifests inside the tree.
	mustWriteFile(b, root, "dir_0/dir_0/dir_0/package.json", []byte(`{"name":"bench-pkg","version":"1.0.0"}`))
	mustWriteFile(b, root, "dir_1/dir_1/dir_1/go.mod", []byte("module example.com/bench\n\ngo 1.22\n\nrequire golang.org/x/text v0.14.0\n"))
	return root
}

func BenchmarkScan_DeepTree(b *testing.B) {
	root := createDeepBenchmarkTree(b)

	for _, mode := range []struct {
		name      string
		scanRoots func(path string) []*scalibrfs.ScanRoot
	}{
		{name: "real_fs", scanRoots: scalibrfs.RealFSScanRoots},
		{name: "confined_fs", scanRoots: scalibrfs.ConfinedScanRoots},
	} {
		b.Run(mode.name, func(b *testing.B) {
			b.Run("default_plugins", func(b *testing.B) {
				plugins := []plugin.Plugin{
					mustNewExtractor(b, dpkg.New),
					mustNewExtractor(b, apk.New),
					mustNewExtractor(b, packagejson.New),
					mustNewExtractor(b, gomod.New),
					mustNewExtractor(b, wheelegg.New),
					mustNewExtractor(b, gitrepo.New),
				}
				for b.Loop() {
					cfg := &scalibr.ScanConfig{
						ScanRoots:   mode.scanRoots(root),
						Plugins:     plugins,
						MaxFileSize: 10 * 1024 * 1024,
					}
					sr := scalibr.New().Scan(b.Context(), cfg)
					if sr.Status.Status != plugin.ScanStatusSucceeded {
						b.Fatalf("Scan() status = %v, want SUCCEEDED", sr.Status)
					}
				}
			})

			b.Run("stat_extractor", func(b *testing.B) {
				// Same tree, also calling api.Stat() on 20% of files (.bin) via execStatExtractor.
				plugins := []plugin.Plugin{
					mustNewExtractor(b, packagejson.New),
					mustNewExtractor(b, gomod.New),
					execStatExtractor{},
				}
				for b.Loop() {
					cfg := &scalibr.ScanConfig{
						ScanRoots:   mode.scanRoots(root),
						Plugins:     plugins,
						MaxFileSize: 10 * 1024 * 1024,
					}
					sr := scalibr.New().Scan(b.Context(), cfg)
					if sr.Status.Status != plugin.ScanStatusSucceeded {
						b.Fatalf("Scan() status = %v, want SUCCEEDED", sr.Status)
					}
				}
			})
		})
	}
}
