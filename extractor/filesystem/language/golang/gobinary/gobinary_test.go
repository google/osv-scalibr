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

package gobinary_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		mode             fs.FileMode
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
		wantResultMetric stats.FileRequiredResult
	}{
		{
			name:             "user executable",
			path:             "some/path/a",
			mode:             0766,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "group executable",
			path:             "some/path/a",
			mode:             0676,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "other executable",
			path:             "some/path/a",
			mode:             0667,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "windows exe",
			path:             "some/path/a.exe",
			mode:             0666,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "executable required if size less than maxFileSizeBytes",
			path:             "some/path/a",
			mode:             0766,
			fileSizeBytes:    100,
			maxFileSizeBytes: 1000,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "executable required if size equal to maxFileSizeBytes",
			path:             "some/path/a",
			mode:             0766,
			fileSizeBytes:    1000,
			maxFileSizeBytes: 1000,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "executable not required if size greater than maxFileSizeBytes",
			path:             "some/path/a",
			mode:             0766,
			fileSizeBytes:    1000,
			maxFileSizeBytes: 100,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "executable required if maxFileSizeBytes explicitly set to 0",
			path:             "some/path/a",
			mode:             0766,
			fileSizeBytes:    1000,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e := gobinary.New(gobinary.Config{
				Stats:            collector,
				MaxFileSizeBytes: tt.maxFileSizeBytes,
			})

			// Set a default file size if not specified.
			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1000
			}

			if got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: tt.mode,
				FileSize: fileSizeBytes,
			})); got != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.wantRequired)
			}

			gotResultMetric := collector.FileRequiredResult(tt.path)
			if gotResultMetric != tt.wantResultMetric {
				t.Errorf("FileRequired(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		cfg              *gobinary.Config
		path             string
		wantPackages     []*extractor.Package
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name:         "binary_with_module_replacement-darwin-amd64",
			path:         "testdata/binary_with_module_replacement-darwin-amd64",
			wantPackages: createPackagesWithMain(append(BinaryWithModuleReplacementPackages, Toolchain), "testdata/binary_with_module_replacement-darwin-amd64"),
		},
		{
			name:         "binary_with_module_replacement-darwin-arm64",
			path:         "testdata/binary_with_module_replacement-darwin-arm64",
			wantPackages: createPackagesWithMain(append(BinaryWithModuleReplacementPackages, Toolchain), "testdata/binary_with_module_replacement-darwin-arm64"),
		},
		{
			name:         "binary_with_module_replacement-linux-386",
			path:         "testdata/binary_with_module_replacement-linux-386",
			wantPackages: createPackagesWithMain(append(BinaryWithModuleReplacementPackages, Toolchain), "testdata/binary_with_module_replacement-linux-386"),
		},
		{
			name:         "binary_with_module_replacement-linux-amd64",
			path:         "testdata/binary_with_module_replacement-linux-amd64",
			wantPackages: createPackagesWithMain(append(BinaryWithModuleReplacementPackages, Toolchain), "testdata/binary_with_module_replacement-linux-amd64"),
		},
		{
			name:         "binary_with_module_replacement-linux-arm64",
			path:         "testdata/binary_with_module_replacement-linux-arm64",
			wantPackages: createPackagesWithMain(append(BinaryWithModuleReplacementPackages, Toolchain), "testdata/binary_with_module_replacement-linux-arm64"),
		},
		{
			name:         "binary_with_module_replacement-windows-386",
			path:         "testdata/binary_with_module_replacement-windows-386",
			wantPackages: createPackagesWithMain(append(BinaryWithModuleReplacementPackages, Toolchain), "testdata/binary_with_module_replacement-windows-386"),
		},
		{
			name:         "binary_with_module_replacement-windows-amd64",
			path:         "testdata/binary_with_module_replacement-windows-amd64",
			wantPackages: createPackagesWithMain(append(BinaryWithModuleReplacementPackages, Toolchain), "testdata/binary_with_module_replacement-windows-amd64"),
		},
		{
			name:         "binary_with_module_replacement-windows-arm64",
			path:         "testdata/binary_with_module_replacement-windows-arm64",
			wantPackages: createPackagesWithMain(append(BinaryWithModuleReplacementPackages, Toolchain), "testdata/binary_with_module_replacement-windows-arm64"),
		},
		{
			name:         "binary_with_modules-darwin-amd64",
			path:         "testdata/binary_with_modules-darwin-amd64",
			wantPackages: createPackagesWithMain(append(BinaryWithModulesPackages, Toolchain), "testdata/binary_with_modules-darwin-amd64"),
		},
		{
			name:         "binary_with_modules-darwin-arm64",
			path:         "testdata/binary_with_modules-darwin-arm64",
			wantPackages: createPackagesWithMain(append(BinaryWithModulesPackages, Toolchain), "testdata/binary_with_modules-darwin-arm64"),
		},
		{
			name:         "binary_with_modules-linux-386",
			path:         "testdata/binary_with_modules-linux-386",
			wantPackages: createPackagesWithMain(append(BinaryWithModulesPackages, Toolchain), "testdata/binary_with_modules-linux-386"),
		},
		{
			name:         "binary_with_modules-linux-amd64",
			path:         "testdata/binary_with_modules-linux-amd64",
			wantPackages: createPackagesWithMain(append(BinaryWithModulesPackages, Toolchain), "testdata/binary_with_modules-linux-amd64"),
		},
		{
			name:         "binary_with_modules-linux-arm64",
			path:         "testdata/binary_with_modules-linux-arm64",
			wantPackages: createPackagesWithMain(append(BinaryWithModulesPackages, Toolchain), "testdata/binary_with_modules-linux-arm64"),
		},
		{
			name:         "binary_with_modules-windows-386",
			path:         "testdata/binary_with_modules-windows-386",
			wantPackages: createPackagesWithMain(append(BinaryWithModulesPackagesWindows, Toolchain), "testdata/binary_with_modules-windows-386"),
		},
		{
			name:         "binary_with_modules-windows-amd64",
			path:         "testdata/binary_with_modules-windows-amd64",
			wantPackages: createPackagesWithMain(append(BinaryWithModulesPackagesWindows, Toolchain), "testdata/binary_with_modules-windows-amd64"),
		},
		{
			name:         "binary_with_modules-windows-arm64",
			path:         "testdata/binary_with_modules-windows-arm64",
			wantPackages: createPackagesWithMain(append(BinaryWithModulesPackagesWindows, Toolchain), "testdata/binary_with_modules-windows-arm64"),
		},
		{
			name:         "nginx-ingress-controller with version from content off",
			path:         "testdata/nginx-ingress-controller",
			wantPackages: createPackages(append(BinaryWithModulesPackagesNginx, goPackage("k8s.io/ingress-nginx", "(devel)")), "testdata/nginx-ingress-controller"),
		},
		{
			name: "nginx-ingress-controller with version from content on",
			path: "testdata/nginx-ingress-controller",
			cfg: func() *gobinary.Config {
				cfg := gobinary.DefaultConfig()
				cfg.VersionFromContent = true
				return &cfg
			}(),
			wantPackages: createPackages(append(BinaryWithModulesPackagesNginx, goPackage("k8s.io/ingress-nginx", "1.11.4")), "testdata/nginx-ingress-controller"),
		},
		{
			name:             "dummy file that fails to parse will log an error metric, but won't fail extraction",
			path:             "testdata/dummy",
			wantPackages:     nil,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.path)
			if err != nil {
				t.Fatalf("os.Open(%s) unexpected error: %v", tt.path, err)
			}
			defer f.Close()

			info, err := f.Stat()
			if err != nil {
				t.Fatalf("f.Stat() for %q unexpected error: %v", tt.path, err)
			}

			collector := testcollector.New()

			input := &filesystem.ScanInput{FS: scalibrfs.DirFS("."), Path: tt.path, Info: info, Reader: f}

			cfg := gobinary.DefaultConfig()
			if tt.cfg != nil {
				cfg = *tt.cfg
			}
			cfg.Stats = collector

			e := gobinary.New(cfg)
			got, err := e.Extract(context.Background(), input)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Extract(%s) got error: %v, want error: %v", tt.path, err, tt.wantErr)
			}
			sort := func(a, b *extractor.Package) bool { return a.Name < b.Name }
			wantInv := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(sort)); diff != "" {
				t.Fatalf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}

			wantResultMetric := tt.wantResultMetric
			if wantResultMetric == "" && tt.wantErr == nil {
				wantResultMetric = stats.FileExtractedResultSuccess
			}
			gotResultMetric := collector.FileExtractedResult(tt.path)
			if gotResultMetric != wantResultMetric {
				t.Errorf("Extract(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, wantResultMetric)
			}

			gotFileSizeMetric := collector.FileExtractedFileSize(tt.path)
			if gotFileSizeMetric != info.Size() {
				t.Errorf("Extract(%s) recorded file size %v, want file size %v", tt.path, gotFileSizeMetric, info.Size())
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	e := gobinary.Extractor{}
	p := &extractor.Package{
		Name:      "github.com/google/osv-scalibr",
		Version:   "1.2.3",
		Locations: []string{"location"},
	}
	want := &purl.PackageURL{
		Type:      purl.TypeGolang,
		Name:      "osv-scalibr",
		Namespace: "github.com/google",
		Version:   "1.2.3",
	}
	got := e.ToPURL(p)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ToPURL(%v) (-want +got):\n%s", p, diff)
	}
}

var (
	// BinaryWithModulesPackagesWindows is a list of packages built into the
	// binary_with_modules-* testdata binaries, but only on Windows, where there
	// is an indirect dependency that is not built-in.
	BinaryWithModulesPackagesWindows = []*extractor.Package{
		// direct dependencies
		goPackage("github.com/ulikunitz/xz", "0.5.11"),
		goPackage("github.com/gin-gonic/gin", "1.8.1"),

		// indirect dependencies
		goPackage("github.com/gin-contrib/sse", "0.1.0"),
		goPackage("github.com/go-playground/locales", "0.14.0"),
		goPackage("github.com/go-playground/universal-translator", "0.18.0"),
		goPackage("github.com/go-playground/validator/v10", "10.11.1"),
		goPackage("github.com/leodido/go-urn", "1.2.1"),
		goPackage("github.com/mattn/go-isatty", "0.0.16"),
		goPackage("github.com/pelletier/go-toml/v2", "2.0.6"),
		goPackage("github.com/ugorji/go/codec", "1.2.7"),
		goPackage("golang.org/x/crypto", "0.4.0"),
		goPackage("golang.org/x/net", "0.4.0"),
		goPackage("golang.org/x/text", "0.5.0"),
		goPackage("google.golang.org/protobuf", "1.28.1"),
		goPackage("gopkg.in/yaml.v2", "2.4.0"),
	}

	// BinaryWithModulesPackages is a list of packages built into the
	// binary_with_modules-* testdata binaries.
	BinaryWithModulesPackages = append(
		BinaryWithModulesPackagesWindows,
		goPackage("golang.org/x/sys", "0.3.0"),
	)

	// BinaryWithModuleReplacementPackages is a list of packages built into the
	// binary_with_module_replacement-* testdata binaries.
	BinaryWithModuleReplacementPackages = []*extractor.Package{
		// this binary replaces golang.org/x/xerrors => github.com/golang/xerrors
		goPackage("github.com/golang/xerrors", "0.0.0-20220907171357-04be3eba64a2"),
	}

	BinaryWithModulesPackagesNginx = []*extractor.Package{
		goPackage("dario.cat/mergo", "1.0.1"),
		goPackage("github.com/armon/go-proxyproto", "0.1.0"),
		goPackage("github.com/beorn7/perks", "1.0.1"),
		goPackage("github.com/blang/semver/v4", "4.0.0"),
		goPackage("github.com/cespare/xxhash/v2", "2.3.0"),
		goPackage("github.com/coreos/go-systemd/v22", "22.5.0"),
		goPackage("github.com/cyphar/filepath-securejoin", "0.3.5"),
		goPackage("github.com/davecgh/go-spew", "1.1.2-0.20180830191138-d8f796af33cc"),
		goPackage("github.com/eapache/channels", "1.1.0"),
		goPackage("github.com/eapache/queue", "1.1.0"),
		goPackage("github.com/emicklei/go-restful/v3", "3.12.0"),
		goPackage("github.com/fsnotify/fsnotify", "1.8.0"),
		goPackage("github.com/fullsailor/pkcs7", "0.0.0-20190404230743-d7302db945fa"),
		goPackage("github.com/fxamacker/cbor/v2", "2.7.0"),
		goPackage("github.com/go-logr/logr", "1.4.2"),
		goPackage("github.com/go-openapi/jsonpointer", "0.21.0"),
		goPackage("github.com/go-openapi/jsonreference", "0.21.0"),
		goPackage("github.com/go-openapi/swag", "0.23.0"),
		goPackage("github.com/godbus/dbus/v5", "5.1.0"),
		goPackage("github.com/gogo/protobuf", "1.3.2"),
		goPackage("github.com/golang/protobuf", "1.5.4"),
		goPackage("github.com/google/gnostic-models", "0.6.8"),
		goPackage("github.com/google/go-cmp", "0.6.0"),
		goPackage("github.com/google/gofuzz", "1.2.0"),
		goPackage("github.com/google/uuid", "1.6.0"),
		goPackage("github.com/josharian/intern", "1.0.0"),
		goPackage("github.com/json-iterator/go", "1.1.12"),
		goPackage("github.com/klauspost/compress", "1.17.9"),
		goPackage("github.com/mailru/easyjson", "0.7.7"),
		goPackage("github.com/mitchellh/go-ps", "1.0.0"),
		goPackage("github.com/mitchellh/hashstructure/v2", "2.0.2"),
		goPackage("github.com/mitchellh/mapstructure", "1.5.0"),
		goPackage("github.com/moby/sys/mountinfo", "0.7.1"),
		goPackage("github.com/moby/sys/userns", "0.1.0"),
		goPackage("github.com/modern-go/concurrent", "0.0.0-20180306012644-bacd9c7ef1dd"),
		goPackage("github.com/modern-go/reflect2", "1.0.2"),
		goPackage("github.com/munnerz/goautoneg", "0.0.0-20191010083416-a7dc8b61c822"),
		goPackage("github.com/ncabatoff/go-seq", "0.0.0-20180805175032-b08ef85ed833"),
		goPackage("github.com/ncabatoff/process-exporter", "0.8.4"),
		goPackage("github.com/opencontainers/runc", "1.2.3"),
		goPackage("github.com/opencontainers/runtime-spec", "1.2.0"),
		goPackage("github.com/pkg/errors", "0.9.1"),
		goPackage("github.com/prometheus/client_golang", "1.20.5"),
		goPackage("github.com/prometheus/client_model", "0.6.1"),
		goPackage("github.com/prometheus/common", "0.61.0"),
		goPackage("github.com/prometheus/procfs", "0.15.1"),
		goPackage("github.com/sirupsen/logrus", "1.9.3"),
		goPackage("github.com/spf13/cobra", "1.8.1"),
		goPackage("github.com/spf13/pflag", "1.0.5"),
		goPackage("github.com/x448/float16", "0.8.4"),
		goPackage("github.com/zakjan/cert-chain-resolver", "0.0.0-20221221105603-fcedb00c5b30"),
		goPackage("go", "1.23.4"),
		goPackage("go.opentelemetry.io/otel", "1.31.0"),
		goPackage("go.opentelemetry.io/otel/trace", "1.31.0"),
		goPackage("golang.org/x/exp", "0.0.0-20240719175910-8a7402abbf56"),
		goPackage("golang.org/x/net", "0.33.0"),
		goPackage("golang.org/x/oauth2", "0.24.0"),
		goPackage("golang.org/x/sys", "0.28.0"),
		goPackage("golang.org/x/term", "0.27.0"),
		goPackage("golang.org/x/text", "0.21.0"),
		goPackage("golang.org/x/time", "0.7.0"),
		goPackage("google.golang.org/protobuf", "1.35.2"),
		goPackage("gopkg.in/evanphx/json-patch.v4", "4.12.0"),
		goPackage("gopkg.in/go-playground/pool.v3", "3.1.1"),
		goPackage("gopkg.in/inf.v0", "0.9.1"),
		goPackage("gopkg.in/mcuadros/go-syslog.v2", "2.3.0"),
		goPackage("gopkg.in/yaml.v3", "3.0.1"),
		goPackage("k8s.io/api", "0.32.0"),
		goPackage("k8s.io/apimachinery", "0.32.0"),
		goPackage("k8s.io/apiserver", "0.32.0"),
		goPackage("k8s.io/client-go", "0.32.0"),
		goPackage("k8s.io/component-base", "0.32.0"),
		goPackage("k8s.io/klog/v2", "2.130.1"),
		goPackage("k8s.io/kube-openapi", "0.0.0-20241105132330-32ad38e42d3f"),
		goPackage("k8s.io/utils", "0.0.0-20241104100929-3ea5e8cea738"),
		goPackage("pault.ag/go/sniff", "0.0.0-20200207005214-cf7e4d167732"),
		goPackage("sigs.k8s.io/json", "0.0.0-20241010143419-9aa6b5e7a4b3"),
		goPackage("sigs.k8s.io/structured-merge-diff/v4", "4.4.2"),
		goPackage("sigs.k8s.io/yaml", "1.4.0"),
	}

	Toolchain = goPackage("go", "1.22.0")
)

func goPackage(name, version string) *extractor.Package {
	return &extractor.Package{Name: name, Version: version}
}

func createPackagesWithMain(pkgs []*extractor.Package, location string) []*extractor.Package {
	res := createPackages(pkgs, location)
	// Main package
	mainName := strings.Split(strings.TrimPrefix(location, "testdata/"), "-")[0]
	res = append(res, &extractor.Package{
		Name: mainName, Version: "(devel)", Locations: []string{location},
	})
	return res
}

func createPackages(pkgs []*extractor.Package, location string) []*extractor.Package {
	res := []*extractor.Package{}
	for _, p := range pkgs {
		res = append(res, &extractor.Package{
			Name: p.Name, Version: p.Version, Locations: []string{location},
		})
	}
	return res
}
