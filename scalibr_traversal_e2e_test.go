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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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

func packageSet(sr *scalibr.ScanResult) map[string]bool {
	got := make(map[string]bool, len(sr.Inventory.Packages))
	for _, p := range sr.Inventory.Packages {
		got[p.Name+"@"+p.Version] = true
	}
	return got
}

func TestScan_RealFS_MultiPluginEndToEnd(t *testing.T) {
	parent := t.TempDir()
	outside := filepath.Join(parent, "outside")
	scanRoot := filepath.Join(parent, "rootfs")
	if err := os.MkdirAll(scanRoot, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", scanRoot, err)
	}

	pemKey := generateTestECPrivateKeyPEM(t)

	// OS packages (Debian dpkg + Alpine apk).
	mustWriteFile(t, scanRoot, "usr/lib/os-release", []byte("ID=debian\nVERSION_ID=\"12\"\n"))
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

	// Deeply nested directory (> maxSubRootDepth = 32) to verify sub-root depth cap transitions cleanly.
	deepParts := make([]string, 40)
	for i := range deepParts {
		deepParts[i] = fmt.Sprintf("d%02d", i)
	}
	deepPkgPath := strings.Join(append([]string{"deep"}, deepParts...), "/") + "/package.json"
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

	// Symlink confinement and intra-guest absolute symlink fixtures on non-Windows.
	if runtime.GOOS != "windows" {
		if err := os.MkdirAll(filepath.Join(scanRoot, "etc"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/usr/lib/os-release", filepath.Join(scanRoot, "etc", "os-release")); err != nil {
			t.Fatal(err)
		}

		// Host files outside scanRoot that escaping symlinks attempt to read.
		mustWriteFile(t, outside, "package.json", []byte(`{"name":"escaped-file-pkg","version":"6.6.6"}`))
		mustWriteFile(t, outside, "dir/package.json", []byte(`{"name":"escaped-dir-pkg","version":"6.6.6"}`))
		mustWriteFile(t, outside, "host.pem", pemKey)

		escapeDir := filepath.Join(scanRoot, "escape")
		if err := os.MkdirAll(filepath.Join(escapeDir, "abs"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../../outside/package.json", filepath.Join(escapeDir, "package.json")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(outside, "package.json"), filepath.Join(escapeDir, "abs", "package.json")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(outside, "host.pem"), filepath.Join(escapeDir, "host.pem")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(outside, "dir"), filepath.Join(escapeDir, "outside-dir")); err != nil {
			t.Fatal(err)
		}
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
		DirsToSkip:   []string{filepath.Join(scanRoot, "skip-by-name")},
		SkipDirRegex: regexp.MustCompile(`^skip-by-regex$`),
		UseGitignore: true,
		MaxFileSize:  256 * 1024,
	}

	sr := scalibr.New().Scan(t.Context(), cfg)
	if sr.Status.Status != plugin.ScanStatusSucceeded {
		t.Fatalf("Scan() status = %v (reason: %s), want Succeeded", sr.Status.Status, sr.Status.FailureReason)
	}

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
			t.Errorf("missing expected package %q; got packages: %v", want, pkgs)
		}
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
			t.Errorf("unexpectedly extracted forbidden package %q", bad)
		}
	}

	// Verify Veles secret extraction found etc/ssl/app.pem and never escaped to outside/host.pem.
	var secretPaths []string
	for _, s := range sr.Inventory.Secrets {
		secretPaths = append(secretPaths, s.Location.PathOrEmpty())
	}
	if len(secretPaths) != 1 || secretPaths[0] != "etc/ssl/app.pem" {
		t.Errorf("Secrets locations = %v, want [etc/ssl/app.pem]", secretPaths)
	}

	// Also verify ReadSymlinks: true actively blocks escaping symlinks while
	// still extracting valid intra-root relative and absolute symlinks.
	if runtime.GOOS != "windows" {
		t.Run("read_symlinks_confinement", func(t *testing.T) {
			if err := os.MkdirAll(filepath.Join(scanRoot, "links", "rel"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(scanRoot, "links", "abs"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../../srv/web/app/package.json", filepath.Join(scanRoot, "links", "rel", "package.json")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/srv/web/app/package.json", filepath.Join(scanRoot, "links", "abs", "package.json")); err != nil {
				t.Fatal(err)
			}

			symCfg := &scalibr.ScanConfig{
				ScanRoots: scalibrfs.RealFSScanRoots(scanRoot),
				Plugins: []plugin.Plugin{
					mustNewExtractor(t, packagejson.New),
					fromVelesDetector(t, privatekey.NewDetector(), "secrets/privatekey", 0),
				},
				ReadSymlinks: true,
			}
			symSR := scalibr.New().Scan(t.Context(), symCfg)
			if symSR.Status.Status != plugin.ScanStatusSucceeded {
				t.Fatalf("ReadSymlinks Scan() status = %v (reason: %s), want Succeeded", symSR.Status.Status, symSR.Status.FailureReason)
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
					foundLocations = append(foundLocations, p.Location.Descriptor.File.Path)
				}
			}
			for _, wantLoc := range []string{"srv/web/app/package.json", "links/rel/package.json", "links/abs/package.json"} {
				found := false
				for _, gotLoc := range foundLocations {
					if gotLoc == wantLoc {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("missing expected web-app extraction at %q; got locations: %v", wantLoc, foundLocations)
				}
			}
			for _, s := range symSR.Inventory.Secrets {
				if strings.HasPrefix(s.Location.PathOrEmpty(), "escape/") {
					t.Errorf("ReadSymlinks scan extracted escaped secret at %q", s.Location.PathOrEmpty())
				}
			}
		})
	}
}

type tarEntry struct {
	name    string
	content []byte
}

func buildTarBytes(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     0o644,
			Typeflag: tar.TypeReg,
			Size:     int64(len(e.content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%q): %v", e.name, err)
		}
		if len(e.content) > 0 {
			if _, err := tw.Write(e.content); err != nil {
				t.Fatalf("Write(%q): %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	return buf.Bytes()
}

func TestScan_EmbeddedFS_ArchiveEndToEnd(t *testing.T) {
	scanRoot := t.TempDir()
	pemKey := generateTestECPrivateKeyPEM(t)

	// Embedded .tar.gz archive containing nested OS + language packages and a secret.
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	rawTar := buildTarBytes(t, []tarEntry{
		{name: "var/lib/dpkg/status", content: []byte("Package: archive-dpkg\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.1.0\n\n")},
		{name: "srv/nested/deep/package.json", content: []byte(`{"name":"archive-npm","version":"4.2.0"}`)},
		{name: "keys/archive.pem", content: pemKey},
	})
	if _, err := gw.Write(rawTar); err != nil {
		t.Fatalf("gzip Write: %v", err)
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
	if sr.Status.Status != plugin.ScanStatusSucceeded {
		t.Fatalf("Scan() status = %v (reason: %s), want Succeeded", sr.Status.Status, sr.Status.FailureReason)
	}

	// Verify the embedded archive filesystem was discovered, traversed, and cleaned up.
	var sawArchive bool
	for _, efs := range sr.Inventory.EmbeddedFSs {
		if strings.HasPrefix(efs.Path, "archives/bundle.tar.gz") {
			sawArchive = true
		}
		for _, tmpPath := range efs.TempPaths {
			if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
				t.Errorf("EmbeddedFS temp path %q still exists after Scan(): %v", tmpPath, err)
			}
		}
	}
	if !sawArchive {
		t.Error("expected embedded archive filesystem to be discovered")
	}

	pkgs := packageSet(sr)
	for _, want := range []string{"archive-dpkg@3.1.0", "archive-npm@4.2.0"} {
		if !pkgs[want] {
			t.Errorf("missing embedded archive package %q; got: %v", want, pkgs)
		}
	}

	var secretPaths []string
	for _, s := range sr.Inventory.Secrets {
		secretPaths = append(secretPaths, s.Location.PathOrEmpty())
	}
	if len(secretPaths) != 1 || !strings.HasSuffix(secretPaths[0], "keys/archive.pem") {
		t.Errorf("Secrets locations = %v, want 1 secret ending in keys/archive.pem", secretPaths)
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

func createDeepBenchmarkTree(b *testing.B, depth, fanout, filesPerDir int) string {
	b.Helper()
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
	// Seed a few real manifests at the bottom of the tree.
	mustWriteFile(b, root, "dir_0/dir_0/dir_0/package.json", []byte(`{"name":"bench-pkg","version":"1.0.0"}`))
	mustWriteFile(b, root, "dir_1/dir_1/dir_1/go.mod", []byte("module example.com/bench\n\ngo 1.22\n\nrequire golang.org/x/text v0.14.0\n"))
	return root
}

func BenchmarkScan_RealFS_DeepTree(b *testing.B) {
	// depth=7, fanout=2 -> 255 directories; 20 files/dir -> 5,100 files.
	root := createDeepBenchmarkTree(b, 7, 2, 20)
	plugins := []plugin.Plugin{
		mustNewExtractor(b, dpkg.New),
		mustNewExtractor(b, apk.New),
		mustNewExtractor(b, packagejson.New),
		mustNewExtractor(b, gomod.New),
		mustNewExtractor(b, wheelegg.New),
		mustNewExtractor(b, gitrepo.New),
	}

	b.ResetTimer()
	for b.Loop() {
		cfg := &scalibr.ScanConfig{
			ScanRoots:   scalibrfs.RealFSScanRoots(root),
			Plugins:     plugins,
			MaxFileSize: 10 * 1024 * 1024,
		}
		sr := scalibr.New().Scan(b.Context(), cfg)
		if sr.Status.Status != plugin.ScanStatusSucceeded {
			b.Fatalf("Scan() failed: %s", sr.Status.FailureReason)
		}
	}
}

func BenchmarkScan_RealFS_DeepTreeWithStatExtractor(b *testing.B) {
	// Same tree, also calling api.Stat() on 20% of files (.bin) via IsInterestingExecutable.
	root := createDeepBenchmarkTree(b, 7, 2, 20)
	plugins := []plugin.Plugin{
		mustNewExtractor(b, packagejson.New),
		mustNewExtractor(b, gomod.New),
		execStatExtractor{},
	}

	b.ResetTimer()
	for b.Loop() {
		cfg := &scalibr.ScanConfig{
			ScanRoots:   scalibrfs.RealFSScanRoots(root),
			Plugins:     plugins,
			MaxFileSize: 10 * 1024 * 1024,
		}
		sr := scalibr.New().Scan(b.Context(), cfg)
		if sr.Status.Status != plugin.ScanStatusSucceeded {
			b.Fatalf("Scan() failed: %s", sr.Status.FailureReason)
		}
	}
}
