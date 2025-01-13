// Copyright 2024 Google LLC
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

package proto_test

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/binary/proto"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/extractor"
	ctrdfs "github.com/google/osv-scalibr/extractor/filesystem/containers/containerd"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/depsjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/extractor/filesystem/os/pacman"
	"github.com/google/osv-scalibr/extractor/filesystem/os/portage"
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpm"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	ctrdruntime "github.com/google/osv-scalibr/extractor/standalone/containers/containerd"
	winmetadata "github.com/google/osv-scalibr/extractor/standalone/windows/common/metadata"
	"github.com/google/osv-scalibr/extractor/standalone/windows/dismpatch"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"google.golang.org/protobuf/testing/protocmp"

	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestWrite(t *testing.T) {
	testDirPath := t.TempDir()
	var result = &spb.ScanResult{Version: "1.0.0"}
	testCases := []struct {
		desc           string
		path           string
		expectedPrefix string
	}{
		{
			desc:           "textproto",
			path:           "output.textproto",
			expectedPrefix: "version:",
		},
		{
			desc:           "binproto",
			path:           "output.binproto",
			expectedPrefix: "\x0a\x051.0.0",
		},
		{
			desc:           "gzipped file",
			path:           "output.textproto.gz",
			expectedPrefix: "\x1f\x8b",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			fullPath := filepath.Join(testDirPath, tc.path)
			err := proto.Write(fullPath, result)
			if err != nil {
				t.Fatalf("proto.Write(%s, %v) returned an error: %v", fullPath, result, err)
			}

			content, err := os.ReadFile(fullPath)
			if err != nil {
				t.Fatalf("error while reading %s: %v", fullPath, err)
			}
			prefix := content[:len(tc.expectedPrefix)]
			if diff := cmp.Diff(tc.expectedPrefix, string(prefix)); diff != "" {
				t.Errorf("%s contains unexpected prefix, diff (-want +got):\n%s", fullPath, diff)
			}
		})
	}
}

func TestWrite_InvalidFilename(t *testing.T) {
	testDirPath := t.TempDir()
	testPaths := []string{
		"config.invalid-extension",
		"config.invalid-extension.gz",
		"no-extension",
		"no-extension.gz",
	}
	for _, p := range testPaths {
		fullPath := filepath.Join(testDirPath, p)
		if err := proto.Write(fullPath, &spb.ScanResult{}); err == nil ||
			!strings.HasPrefix(err.Error(), "invalid filename") {
			t.Errorf("proto.Write(%s) didn't return an invalid file error: %v", fullPath, err)
		}
	}
}

func TestWriteWithFormat(t *testing.T) {
	testDirPath := t.TempDir()
	var result = &spb.ScanResult{Version: "1.0.0"}
	testCases := []struct {
		desc           string
		format         string
		expectedPrefix string
	}{
		{
			desc:           "textproto",
			format:         "textproto",
			expectedPrefix: "version:",
		},
		{
			desc:           "binproto",
			format:         "binproto",
			expectedPrefix: "\x0a\x051.0.0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			fullPath := filepath.Join(testDirPath, "output")
			err := proto.WriteWithFormat(fullPath, result, tc.format)
			if err != nil {
				t.Fatalf("proto.WriteWithFormat(%s, %v, %s) returned an error: %v", fullPath, result, tc.format, err)
			}

			content, err := os.ReadFile(fullPath)
			if err != nil {
				t.Fatalf("error while reading %s: %v", fullPath, err)
			}
			prefix := content[:len(tc.expectedPrefix)]
			if diff := cmp.Diff(tc.expectedPrefix, string(prefix)); diff != "" {
				t.Errorf("%s contains unexpected prefix, diff (-want +got):\n%s", fullPath, diff)
			}
		})
	}
}

func TestScanResultToProto(t *testing.T) {
	endTime := time.Now()
	startTime := endTime.Add(time.Second * -10)
	success := &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}
	successProto := &spb.ScanStatus{Status: spb.ScanStatus_SUCCEEDED}
	failure := &plugin.ScanStatus{Status: plugin.ScanStatusFailed, FailureReason: "failure"}
	failureProto := &spb.ScanStatus{Status: spb.ScanStatus_FAILED, FailureReason: "failure"}
	purlDPKGInventory := &extractor.Inventory{
		Name:    "software",
		Version: "1.0.0",
		Metadata: &dpkg.Metadata{
			PackageName:       "software",
			PackageVersion:    "1.0.0",
			OSID:              "debian",
			OSVersionCodename: "jammy",
			Maintainer:        "maintainer",
			Architecture:      "amd64",
		},
		Locations: []string{"/file1"},
		Extractor: dpkg.New(dpkg.DefaultConfig()),
	}
	purlDPKGAnnotationInventory := &extractor.Inventory{
		Name:    "software",
		Version: "1.0.0",
		Metadata: &dpkg.Metadata{
			PackageName:       "software",
			PackageVersion:    "1.0.0",
			OSID:              "debian",
			OSVersionCodename: "jammy",
			Maintainer:        "maintainer",
			Architecture:      "amd64",
		},
		Locations:   []string{"/file1"},
		Extractor:   dpkg.New(dpkg.DefaultConfig()),
		Annotations: []extractor.Annotation{extractor.Transitional},
	}
	purlPythonInventory := &extractor.Inventory{
		Name:      "software",
		Version:   "1.0.0",
		Locations: []string{"/file1"},
		Extractor: wheelegg.New(wheelegg.DefaultConfig()),
		Metadata: &wheelegg.PythonPackageMetadata{
			Author:      "author",
			AuthorEmail: "author@corp.com",
		},
	}
	pythonRequirementsInventory := &extractor.Inventory{
		Name:      "foo",
		Version:   "1.0",
		Locations: []string{"/file1"},
		Extractor: requirements.Extractor{},
		Metadata: &requirements.Metadata{
			HashCheckingModeValues: []string{"sha256:123"},
			VersionComparator:      ">=",
		},
	}
	purlJavascriptInventory := &extractor.Inventory{
		Name:    "software",
		Version: "1.0.0",
		Metadata: &packagejson.JavascriptPackageJSONMetadata{
			Maintainers: []*packagejson.Person{
				{
					Name:  "maintainer1",
					Email: "maintainer1@corp.com",
					URL:   "https://blog.maintainer1.com",
				},
				{
					Name:  "maintainer2",
					Email: "maintainer2@corp.com",
				},
			},
		},
		Locations: []string{"/file1"},
		Extractor: &packagejson.Extractor{},
	}

	purlDotnetDepsJSONInventory := &extractor.Inventory{
		Name:    "software",
		Version: "1.0.0",
		Metadata: &depsjson.Metadata{
			PackageName:    "software",
			PackageVersion: "1.0.0",
			Type:           "type",
		},
		Locations: []string{"/file1"},
		Extractor: &depsjson.Extractor{},
	}

	purlDotnetDepsJSONInventoryProto := &spb.Inventory{
		Name:    "software",
		Version: "1.0.0",
		Purl: &spb.Purl{
			Purl:    "pkg:nuget/software@1.0.0",
			Type:    purl.TypeNuget,
			Name:    "software",
			Version: "1.0.0",
		},
		Ecosystem: "NuGet",
		Locations: []string{"/file1"},
		Extractor: "dotnet/depsjson",
		Metadata: &spb.Inventory_DepsjsonMetadata{
			DepsjsonMetadata: &spb.DEPSJSONMetadata{
				PackageName:    "software",
				PackageVersion: "1.0.0",
				Type:           "type",
			},
		},
	}

	windowsInventory := &extractor.Inventory{
		Name:    "windows_server_2019",
		Version: "10.0.17763.3406",
		Metadata: &winmetadata.OSVersion{
			Product:     "windows_server_2019",
			FullVersion: "10.0.17763.3406",
		},
		Extractor: &dismpatch.Extractor{},
	}

	purlDPKGInventoryProto := &spb.Inventory{
		Name:    "software",
		Version: "1.0.0",
		Purl: &spb.Purl{
			Purl:      "pkg:deb/debian/software@1.0.0?arch=amd64&distro=jammy",
			Type:      purl.TypeDebian,
			Namespace: "debian",
			Name:      "software",
			Version:   "1.0.0",
			Qualifiers: []*spb.Qualifier{
				{Key: "arch", Value: "amd64"},
				{Key: "distro", Value: "jammy"},
			},
		},
		Ecosystem: "Debian",
		Metadata: &spb.Inventory_DpkgMetadata{
			DpkgMetadata: &spb.DPKGPackageMetadata{
				PackageName:       "software",
				PackageVersion:    "1.0.0",
				OsId:              "debian",
				OsVersionCodename: "jammy",
				Maintainer:        "maintainer",
				Architecture:      "amd64",
			},
		},
		Locations: []string{"/file1"},
		Extractor: "os/dpkg",
	}
	purlDPKGAnnotationInventoryProto := &spb.Inventory{
		Name:    "software",
		Version: "1.0.0",
		Purl: &spb.Purl{
			Purl:      "pkg:deb/debian/software@1.0.0?arch=amd64&distro=jammy",
			Type:      purl.TypeDebian,
			Namespace: "debian",
			Name:      "software",
			Version:   "1.0.0",
			Qualifiers: []*spb.Qualifier{
				{Key: "arch", Value: "amd64"},
				{Key: "distro", Value: "jammy"},
			},
		},
		Ecosystem: "Debian",
		Metadata: &spb.Inventory_DpkgMetadata{
			DpkgMetadata: &spb.DPKGPackageMetadata{
				PackageName:       "software",
				PackageVersion:    "1.0.0",
				OsId:              "debian",
				OsVersionCodename: "jammy",
				Maintainer:        "maintainer",
				Architecture:      "amd64",
			},
		},
		Locations:   []string{"/file1"},
		Extractor:   "os/dpkg",
		Annotations: []spb.Inventory_AnnotationEnum{spb.Inventory_TRANSITIONAL},
	}
	purlPythonInventoryProto := &spb.Inventory{
		Name:    "software",
		Version: "1.0.0",
		Purl: &spb.Purl{
			Purl:    "pkg:pypi/software@1.0.0",
			Type:    purl.TypePyPi,
			Name:    "software",
			Version: "1.0.0",
		},
		Ecosystem: "PyPI",
		Locations: []string{"/file1"},
		Extractor: "python/wheelegg",
		Metadata: &spb.Inventory_PythonMetadata{
			PythonMetadata: &spb.PythonPackageMetadata{
				Author:      "author",
				AuthorEmail: "author@corp.com",
			},
		},
	}
	pythonRequirementsInventoryProto := &spb.Inventory{
		Name:    "foo",
		Version: "1.0",
		Purl: &spb.Purl{
			Purl:    "pkg:pypi/foo@1.0",
			Type:    purl.TypePyPi,
			Name:    "foo",
			Version: "1.0",
		},
		Ecosystem: "PyPI",
		Locations: []string{"/file1"},
		Extractor: "python/requirements",
		Metadata: &spb.Inventory_PythonRequirementsMetadata{
			PythonRequirementsMetadata: &spb.PythonRequirementsMetadata{
				HashCheckingModeValues: []string{"sha256:123"},
				VersionComparator:      ">=",
			},
		},
	}
	purlJavascriptInventoryProto := &spb.Inventory{
		Name:    "software",
		Version: "1.0.0",
		Purl: &spb.Purl{
			Purl:    "pkg:npm/software@1.0.0",
			Type:    purl.TypeNPM,
			Name:    "software",
			Version: "1.0.0",
		},
		Ecosystem: "npm",
		Locations: []string{"/file1"},
		Extractor: "javascript/packagejson",
		Metadata: &spb.Inventory_JavascriptMetadata{
			JavascriptMetadata: &spb.JavascriptPackageJSONMetadata{
				Maintainers: []string{
					"maintainer1 <maintainer1@corp.com> (https://blog.maintainer1.com)",
					"maintainer2 <maintainer2@corp.com>",
				},
			},
		},
	}
	cdxInventory := &extractor.Inventory{
		Name:    "openssl",
		Version: "1.1.1",
		Metadata: &cdx.Metadata{
			PURL: &purl.PackageURL{
				Type:    purl.TypeGeneric,
				Name:    "openssl",
				Version: "1.1.1",
			},
		},
		Locations: []string{"/openssl"},
		Extractor: &cdx.Extractor{},
	}
	cdxInventoryProto := &spb.Inventory{
		Name:      "openssl",
		Version:   "1.1.1",
		Ecosystem: "generic",
		Purl: &spb.Purl{
			Purl:    "pkg:generic/openssl@1.1.1",
			Type:    purl.TypeGeneric,
			Name:    "openssl",
			Version: "1.1.1",
		},
		Metadata: &spb.Inventory_CdxMetadata{
			CdxMetadata: &spb.CDXPackageMetadata{
				Purl: &spb.Purl{
					Purl:    "pkg:generic/openssl@1.1.1",
					Type:    purl.TypeGeneric,
					Name:    "openssl",
					Version: "1.1.1",
				},
			},
		},
		Locations: []string{"/openssl"},
		Extractor: "sbom/cdx",
	}
	purlRPMInventory := &extractor.Inventory{
		Name:    "openssh-clients",
		Version: "5.3p1",
		Metadata: &rpm.Metadata{
			PackageName:  "openssh-clients",
			SourceRPM:    "openssh-5.3p1-124.el6_10.src.rpm",
			Epoch:        2,
			OSID:         "rhel",
			OSVersionID:  "8.9",
			OSBuildID:    "",
			OSName:       "Red Hat Enterprise Linux",
			Vendor:       "CentOS",
			Architecture: "x86_64",
			License:      "BSD",
		},
		Locations: []string{"/file1"},
		Extractor: rpm.New(rpm.DefaultConfig()),
	}
	purlRPMInventoryProto := &spb.Inventory{
		Name:    "openssh-clients",
		Version: "5.3p1",
		Purl: &spb.Purl{
			Purl:      "pkg:rpm/rhel/openssh-clients@5.3p1?arch=x86_64&distro=rhel-8.9&epoch=2&sourcerpm=openssh-5.3p1-124.el6_10.src.rpm",
			Type:      purl.TypeRPM,
			Namespace: "rhel",
			Name:      "openssh-clients",
			Version:   "5.3p1",
			Qualifiers: []*spb.Qualifier{
				{Key: "arch", Value: "x86_64"},
				{Key: "distro", Value: "rhel-8.9"},
				{Key: "epoch", Value: "2"},
				{Key: "sourcerpm", Value: "openssh-5.3p1-124.el6_10.src.rpm"},
			},
		},
		Ecosystem: "Red Hat",
		Metadata: &spb.Inventory_RpmMetadata{
			RpmMetadata: &spb.RPMPackageMetadata{
				PackageName:  "openssh-clients",
				SourceRpm:    "openssh-5.3p1-124.el6_10.src.rpm",
				Epoch:        2,
				OsId:         "rhel",
				OsVersionId:  "8.9",
				OsBuildId:    "",
				OsName:       "Red Hat Enterprise Linux",
				Vendor:       "CentOS",
				Architecture: "x86_64",
				License:      "BSD",
			},
		},
		Locations: []string{"/file1"},
		Extractor: "os/rpm",
	}
	purlPACMANInventory := &extractor.Inventory{
		Name:    "zstd",
		Version: "1.5.6-1",
		Metadata: &pacman.Metadata{
			PackageName:    "zstd",
			PackageVersion: "1.5.6-1",
			OSID:           "arch",
			OSVersionID:    "20241201.0.284684",
		},
		Locations: []string{"/file1"},
		Extractor: pacman.New(pacman.DefaultConfig()),
	}
	purlPACMANInventoryProto := &spb.Inventory{
		Name:    "zstd",
		Version: "1.5.6-1",
		Purl: &spb.Purl{
			Purl:      "pkg:pacman/arch/zstd@1.5.6-1?distro=20241201.0.284684",
			Type:      purl.TypePacman,
			Namespace: "arch",
			Name:      "zstd",
			Version:   "1.5.6-1",
			Qualifiers: []*spb.Qualifier{
				{Key: "distro", Value: "20241201.0.284684"},
			},
		},
		Ecosystem: "Arch:20241201.0.284684",
		Metadata: &spb.Inventory_PacmanMetadata{
			PacmanMetadata: &spb.PACMANPackageMetadata{
				PackageName:    "zstd",
				PackageVersion: "1.5.6-1",
				OsId:           "arch",
				OsVersionId:    "20241201.0.284684",
			},
		},
		Locations: []string{"/file1"},
		Extractor: "os/pacman",
	}
	purlPORTAGEInventory := &extractor.Inventory{
		Name:    "Capture-Tiny",
		Version: "0.480.0-r1",
		Metadata: &portage.Metadata{
			PackageName:    "Capture-Tiny",
			PackageVersion: "0.480.0-r1",
			OSID:           "gentoo",
			OSVersionID:    "2.17",
		},
		Locations: []string{"/file1"},
		Extractor: portage.New(portage.DefaultConfig()),
	}
	purlPORTAGEInventoryProto := &spb.Inventory{
		Name:    "Capture-Tiny",
		Version: "0.480.0-r1",
		Purl: &spb.Purl{
			Purl:      "pkg:portage/gentoo/Capture-Tiny@0.480.0-r1?distro=2.17",
			Type:      purl.TypePortage,
			Namespace: "gentoo",
			Name:      "Capture-Tiny",
			Version:   "0.480.0-r1",
			Qualifiers: []*spb.Qualifier{
				{Key: "distro", Value: "2.17"},
			},
		},
		Ecosystem: "Gentoo:2.17",
		Metadata: &spb.Inventory_PortageMetadata{
			PortageMetadata: &spb.PortagePackageMetadata{
				PackageName:    "Capture-Tiny",
				PackageVersion: "0.480.0-r1",
				OsId:           "gentoo",
				OsVersionId:    "2.17",
			},
		},
		Locations: []string{"/file1"},
		Extractor: "os/portage",
	}
	containerdInventory := &extractor.Inventory{
		Name:    "gcr.io/google-samples/hello-app:1.0",
		Version: "sha256:b1455e1c4fcc5ea1023c9e3b584cd84b64eb920e332feff690a2829696e379e7",
		Metadata: &ctrdfs.Metadata{
			Namespace:   "default",
			ImageName:   "gcr.io/google-samples/hello-app:1.0",
			ImageDigest: "sha256:b1455e1c4fcc5ea1023c9e3b584cd84b64eb920e332feff690a2829696e379e7",
			Runtime:     "io.containerd.runc.v2",
			PID:         8915,
			Snapshotter: "overlayfs",
			SnapshotKey: "abcweraweroiuojgawer1",
			LowerDir:    "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs",
			UpperDir:    "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/4/fs",
			WorkDir:     "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/4/work",
		},
		Locations: []string{"/file4"},
		Extractor: &ctrdfs.Extractor{},
	}
	containerdInventoryProto := &spb.Inventory{
		Name:      "gcr.io/google-samples/hello-app:1.0",
		Version:   "sha256:b1455e1c4fcc5ea1023c9e3b584cd84b64eb920e332feff690a2829696e379e7",
		Ecosystem: "",
		Metadata: &spb.Inventory_ContainerdContainerMetadata{
			ContainerdContainerMetadata: &spb.ContainerdContainerMetadata{
				NamespaceName: "default",
				ImageName:     "gcr.io/google-samples/hello-app:1.0",
				ImageDigest:   "sha256:b1455e1c4fcc5ea1023c9e3b584cd84b64eb920e332feff690a2829696e379e7",
				Runtime:       "io.containerd.runc.v2",
				Pid:           8915,
				Snapshotter:   "overlayfs",
				SnapshotKey:   "abcweraweroiuojgawer1",
				LowerDir:      "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs",
				UpperDir:      "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/4/fs",
				WorkDir:       "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/4/work",
			},
		},
		Locations: []string{"/file4"},
		Extractor: "containers/containerd",
	}
	containerdRuntimeInventory := &extractor.Inventory{
		Name:    "gcr.io/google-samples/hello-app:1.0",
		Version: "sha256:b1455e1c4fcc5ea1023c9e3b584cd84b64eb920e332feff690a2829696e379e7",
		Metadata: &ctrdruntime.Metadata{
			Namespace:   "default",
			ImageName:   "gcr.io/google-samples/hello-app:1.0",
			ImageDigest: "sha256:b1455e1c4fcc5ea1023c9e3b584cd84b64eb920e332feff690a2829696e379e7",
			Runtime:     "io.containerd.runc.v2",
			ID:          "1234567890",
			PID:         8915,
			RootFS:      "/run/containerd/io.containerd.runtime.v2.task/default/1234567890/rootfs",
		},
		Locations: []string{"/file7"},
		Extractor: &ctrdruntime.Extractor{},
	}
	containerdRuntimeInventoryProto := &spb.Inventory{
		Name:      "gcr.io/google-samples/hello-app:1.0",
		Version:   "sha256:b1455e1c4fcc5ea1023c9e3b584cd84b64eb920e332feff690a2829696e379e7",
		Ecosystem: "",
		Metadata: &spb.Inventory_ContainerdRuntimeContainerMetadata{
			ContainerdRuntimeContainerMetadata: &spb.ContainerdRuntimeContainerMetadata{
				NamespaceName: "default",
				ImageName:     "gcr.io/google-samples/hello-app:1.0",
				ImageDigest:   "sha256:b1455e1c4fcc5ea1023c9e3b584cd84b64eb920e332feff690a2829696e379e7",
				Runtime:       "io.containerd.runc.v2",
				Id:            "1234567890",
				Pid:           8915,
				RootfsPath:    "/run/containerd/io.containerd.runtime.v2.task/default/1234567890/rootfs",
			},
		},
		Locations: []string{"/file7"},
		Extractor: "containers/containerd-runtime",
	}
	windowsInventoryProto := &spb.Inventory{
		Name:    "windows_server_2019",
		Version: "10.0.17763.3406",
		Metadata: &spb.Inventory_WindowsOsVersionMetadata{
			WindowsOsVersionMetadata: &spb.WindowsOSVersion{
				Product:     "windows_server_2019",
				FullVersion: "10.0.17763.3406",
			},
		},
		Purl: &spb.Purl{
			Purl:      "pkg:generic/microsoft/windows_server_2019?buildnumber=10.0.17763.3406",
			Type:      purl.TypeGeneric,
			Namespace: "microsoft",
			Name:      "windows_server_2019",
			Qualifiers: []*spb.Qualifier{
				{
					Key:   "buildnumber",
					Value: "10.0.17763.3406",
				},
			},
		},
		Extractor: "windows/dismpatch",
	}
	purlPythonInventoryWithLayerDetails := &extractor.Inventory{
		Name:      "software",
		Version:   "1.0.0",
		Locations: []string{"/file1"},
		Extractor: wheelegg.New(wheelegg.DefaultConfig()),
		Metadata: &wheelegg.PythonPackageMetadata{
			Author:      "author",
			AuthorEmail: "author@corp.com",
		},
		LayerDetails: &extractor.LayerDetails{
			Index:       0,
			DiffID:      "hash1",
			Command:     "command1",
			InBaseImage: true,
		},
	}
	purlPythonInventoryWithLayerDetailsProto := &spb.Inventory{
		Name:    "software",
		Version: "1.0.0",
		Purl: &spb.Purl{
			Purl:    "pkg:pypi/software@1.0.0",
			Type:    purl.TypePyPi,
			Name:    "software",
			Version: "1.0.0",
		},
		Ecosystem: "PyPI",
		Locations: []string{"/file1"},
		Extractor: "python/wheelegg",
		Metadata: &spb.Inventory_PythonMetadata{
			PythonMetadata: &spb.PythonPackageMetadata{
				Author:      "author",
				AuthorEmail: "author@corp.com",
			},
		},
		LayerDetails: &spb.LayerDetails{
			Index:       0,
			DiffId:      "hash1",
			Command:     "command1",
			InBaseImage: true,
		},
	}

	testCases := []struct {
		desc         string
		res          *scalibr.ScanResult
		want         *spb.ScanResult
		wantErr      error
		excludeForOS []string // skip test for these operating systems
	}{
		{
			desc: "Successful scan",
			res: &scalibr.ScanResult{
				Version:   "1.0.0",
				StartTime: startTime,
				EndTime:   endTime,
				Status:    success,
				PluginStatus: []*plugin.Status{
					{
						Name:    "ext",
						Version: 2,
						Status:  success,
					},
					{
						Name:    "det",
						Version: 3,
						Status:  success,
					},
				},
				Inventories: []*extractor.Inventory{
					purlDPKGInventory,
					purlDPKGAnnotationInventory,
					purlPythonInventory,
					pythonRequirementsInventory,
					purlJavascriptInventory,
					purlDotnetDepsJSONInventory,
					cdxInventory,
					windowsInventory,
					purlPythonInventoryWithLayerDetails,
				},
				Findings: []*detector.Finding{
					{
						Adv: &detector.Advisory{
							ID: &detector.AdvisoryID{
								Publisher: "CVE",
								Reference: "CVE-1234",
							},
							Type:           detector.TypeVulnerability,
							Title:          "Title",
							Description:    "Description",
							Recommendation: "Recommendation",
							Sev: &detector.Severity{
								Severity: detector.SeverityMedium,
								CVSSV2:   &detector.CVSS{BaseScore: 1.0, TemporalScore: 2.0, EnvironmentalScore: 3.0},
								CVSSV3:   &detector.CVSS{BaseScore: 4.0, TemporalScore: 5.0, EnvironmentalScore: 6.0},
							},
						},
						Target: &detector.TargetDetails{
							Location:  []string{"/file2"},
							Inventory: purlDPKGInventory,
						},
						Extra: "extra details",
					},
				},
			},
			want: &spb.ScanResult{
				Version:   "1.0.0",
				StartTime: timestamppb.New(startTime),
				EndTime:   timestamppb.New(endTime),
				Status:    successProto,
				PluginStatus: []*spb.PluginStatus{
					{
						Name:    "ext",
						Version: 2,
						Status:  successProto,
					},
					{
						Name:    "det",
						Version: 3,
						Status:  successProto,
					},
				},
				Inventories: []*spb.Inventory{
					purlDPKGInventoryProto,
					purlDPKGAnnotationInventoryProto,
					purlPythonInventoryProto,
					pythonRequirementsInventoryProto,
					purlJavascriptInventoryProto,
					purlDotnetDepsJSONInventoryProto,
					cdxInventoryProto,
					windowsInventoryProto,
					purlPythonInventoryWithLayerDetailsProto,
				},
				Findings: []*spb.Finding{
					{
						Adv: &spb.Advisory{
							Id: &spb.AdvisoryId{
								Publisher: "CVE",
								Reference: "CVE-1234",
							},
							Type:           spb.Advisory_VULNERABILITY,
							Title:          "Title",
							Description:    "Description",
							Recommendation: "Recommendation",
							Sev: &spb.Severity{
								Severity: spb.Severity_MEDIUM,
								CvssV2:   &spb.CVSS{BaseScore: 1.0, TemporalScore: 2.0, EnvironmentalScore: 3.0},
								CvssV3:   &spb.CVSS{BaseScore: 4.0, TemporalScore: 5.0, EnvironmentalScore: 6.0},
							},
						},
						Target: &spb.TargetDetails{
							Location:  []string{"/file2"},
							Inventory: purlDPKGInventoryProto,
						},
						Extra: "extra details",
					},
				},
			},
		},
		{
			desc: "Successful RPM scan linux-only",
			res: &scalibr.ScanResult{
				Version:   "1.0.0",
				StartTime: startTime,
				EndTime:   endTime,
				Status:    success,
				PluginStatus: []*plugin.Status{
					{
						Name:    "ext",
						Version: 2,
						Status:  success,
					},
				},
				Inventories: []*extractor.Inventory{purlRPMInventory},
			},
			want: &spb.ScanResult{
				Version:   "1.0.0",
				StartTime: timestamppb.New(startTime),
				EndTime:   timestamppb.New(endTime),
				Status:    successProto,
				PluginStatus: []*spb.PluginStatus{
					{
						Name:    "ext",
						Version: 2,
						Status:  successProto,
					},
				},
				Inventories: []*spb.Inventory{purlRPMInventoryProto},
				Findings:    []*spb.Finding{},
			},
			excludeForOS: []string{"windows", "darwin"},
		},
		{
			desc: "Successful PACMAN scan linux-only",
			res: &scalibr.ScanResult{
				Version:   "1.0.0",
				StartTime: startTime,
				EndTime:   endTime,
				Status:    success,
				PluginStatus: []*plugin.Status{
					{
						Name:    "ext",
						Version: 2,
						Status:  success,
					},
				},
				Inventories: []*extractor.Inventory{purlPACMANInventory},
			},
			want: &spb.ScanResult{
				Version:   "1.0.0",
				StartTime: timestamppb.New(startTime),
				EndTime:   timestamppb.New(endTime),
				Status:    successProto,
				PluginStatus: []*spb.PluginStatus{
					{
						Name:    "ext",
						Version: 2,
						Status:  successProto,
					},
				},
				Inventories: []*spb.Inventory{purlPACMANInventoryProto},
				Findings:    []*spb.Finding{},
			},
			excludeForOS: []string{"windows", "darwin"},
		},
		{
			desc: "Successful PORTAGE scan linux-only",
			res: &scalibr.ScanResult{
				Version:   "1.0.0",
				StartTime: startTime,
				EndTime:   endTime,
				Status:    success,
				PluginStatus: []*plugin.Status{
					{
						Name:    "ext",
						Version: 2,
						Status:  success,
					},
				},
				Inventories: []*extractor.Inventory{purlPORTAGEInventory},
			},
			want: &spb.ScanResult{
				Version:   "1.0.0",
				StartTime: timestamppb.New(startTime),
				EndTime:   timestamppb.New(endTime),
				Status:    successProto,
				PluginStatus: []*spb.PluginStatus{
					{
						Name:    "ext",
						Version: 2,
						Status:  successProto,
					},
				},
				Inventories: []*spb.Inventory{purlPORTAGEInventoryProto},
				Findings:    []*spb.Finding{},
			},
			excludeForOS: []string{"windows", "darwin"},
		},
		{
			desc: "Successful containerd scan linux-only",
			res: &scalibr.ScanResult{
				Version:   "1.0.0",
				StartTime: startTime,
				EndTime:   endTime,
				Status:    success,
				PluginStatus: []*plugin.Status{
					{
						Name:    "ext",
						Version: 2,
						Status:  success,
					},
				},
				Inventories: []*extractor.Inventory{containerdInventory},
			},
			want: &spb.ScanResult{
				Version:   "1.0.0",
				StartTime: timestamppb.New(startTime),
				EndTime:   timestamppb.New(endTime),
				Status:    successProto,
				PluginStatus: []*spb.PluginStatus{
					{
						Name:    "ext",
						Version: 2,
						Status:  successProto,
					},
				},
				Inventories: []*spb.Inventory{containerdInventoryProto},
				Findings:    []*spb.Finding{},
			},
			// TODO(b/349138656): Remove windows from this exclusion when containerd is supported
			// on Windows.
			excludeForOS: []string{"windows", "darwin"},
		},
		{
			desc: "Successful containerd runtime scan linux-only",
			res: &scalibr.ScanResult{
				Version:   "1.0.0",
				StartTime: startTime,
				EndTime:   endTime,
				Status:    success,
				PluginStatus: []*plugin.Status{
					{
						Name:    "ext",
						Version: 2,
						Status:  success,
					},
				},
				Inventories: []*extractor.Inventory{containerdRuntimeInventory},
			},
			want: &spb.ScanResult{
				Version:   "1.0.0",
				StartTime: timestamppb.New(startTime),
				EndTime:   timestamppb.New(endTime),
				Status:    successProto,
				PluginStatus: []*spb.PluginStatus{
					{
						Name:    "ext",
						Version: 2,
						Status:  successProto,
					},
				},
				Inventories: []*spb.Inventory{containerdRuntimeInventoryProto},
				Findings:    []*spb.Finding{},
			},
			// TODO(b/349138656): Remove windows from this exclusion when containerd is supported
			// on Windows.
			excludeForOS: []string{"windows", "darwin"},
		},
		{
			desc: "no inventory target, still works",
			res: &scalibr.ScanResult{
				Version:   "1.0.0",
				StartTime: startTime,
				EndTime:   endTime,
				Status:    success,
				PluginStatus: []*plugin.Status{
					{
						Name:    "ext",
						Version: 2,
						Status:  success,
					},
					{
						Name:    "det",
						Version: 3,
						Status:  success,
					},
				},
				Inventories: []*extractor.Inventory{purlDPKGInventory, purlPythonInventory, purlJavascriptInventory, cdxInventory},
				Findings: []*detector.Finding{
					{
						Adv: &detector.Advisory{
							ID: &detector.AdvisoryID{
								Publisher: "CVE",
								Reference: "CVE-1234",
							},
							Type:           detector.TypeVulnerability,
							Title:          "Title",
							Description:    "Description",
							Recommendation: "Recommendation",
							Sev: &detector.Severity{
								Severity: detector.SeverityMedium,
								CVSSV2:   &detector.CVSS{BaseScore: 1.0, TemporalScore: 2.0, EnvironmentalScore: 3.0},
								CVSSV3:   &detector.CVSS{BaseScore: 4.0, TemporalScore: 5.0, EnvironmentalScore: 6.0},
							},
						},
						Extra: "extra details",
					},
				},
			},
			want: &spb.ScanResult{
				Version:   "1.0.0",
				StartTime: timestamppb.New(startTime),
				EndTime:   timestamppb.New(endTime),
				Status:    successProto,
				PluginStatus: []*spb.PluginStatus{
					{
						Name:    "ext",
						Version: 2,
						Status:  successProto,
					},
					{
						Name:    "det",
						Version: 3,
						Status:  successProto,
					},
				},
				Inventories: []*spb.Inventory{purlDPKGInventoryProto, purlPythonInventoryProto, purlJavascriptInventoryProto, cdxInventoryProto},
				Findings: []*spb.Finding{
					{
						Adv: &spb.Advisory{
							Id: &spb.AdvisoryId{
								Publisher: "CVE",
								Reference: "CVE-1234",
							},
							Type:           spb.Advisory_VULNERABILITY,
							Title:          "Title",
							Description:    "Description",
							Recommendation: "Recommendation",
							Sev: &spb.Severity{
								Severity: spb.Severity_MEDIUM,
								CvssV2:   &spb.CVSS{BaseScore: 1.0, TemporalScore: 2.0, EnvironmentalScore: 3.0},
								CvssV3:   &spb.CVSS{BaseScore: 4.0, TemporalScore: 5.0, EnvironmentalScore: 6.0},
							},
						},
						Extra: "extra details",
					},
				},
			},
		},
		{
			desc: "advisory without id, should error",
			res: &scalibr.ScanResult{
				Version:   "1.0.0",
				StartTime: startTime,
				EndTime:   endTime,
				Status:    success,
				PluginStatus: []*plugin.Status{
					{
						Name:    "ext",
						Version: 2,
						Status:  success,
					},
					{
						Name:    "det",
						Version: 3,
						Status:  success,
					},
				},
				Inventories: []*extractor.Inventory{purlDPKGInventory, purlPythonInventory, purlJavascriptInventory, cdxInventory},
				Findings: []*detector.Finding{
					{
						Adv: &detector.Advisory{
							Type:           detector.TypeVulnerability,
							Title:          "Title",
							Description:    "Description",
							Recommendation: "Recommendation",
							Sev: &detector.Severity{
								Severity: detector.SeverityMedium,
								CVSSV2:   &detector.CVSS{BaseScore: 1.0, TemporalScore: 2.0, EnvironmentalScore: 3.0},
								CVSSV3:   &detector.CVSS{BaseScore: 4.0, TemporalScore: 5.0, EnvironmentalScore: 6.0},
							},
						},
						Extra: "extra details",
					},
				},
			},
			wantErr: proto.ErrAdvisoryIDMissing,
		},
		{
			desc: "no advisory, should error",
			res: &scalibr.ScanResult{
				Version:   "1.0.0",
				StartTime: startTime,
				EndTime:   endTime,
				Status:    success,
				PluginStatus: []*plugin.Status{
					{
						Name:    "ext",
						Version: 2,
						Status:  success,
					},
					{
						Name:    "det",
						Version: 3,
						Status:  success,
					},
				},
				Inventories: []*extractor.Inventory{purlDPKGInventory, purlPythonInventory, purlJavascriptInventory, cdxInventory},
				Findings: []*detector.Finding{
					{
						Extra: "extra details",
					},
				},
			},
			wantErr: proto.ErrAdvisoryMissing,
		},
		{
			desc: "Failed scan",
			res: &scalibr.ScanResult{
				Version:   "1.0.0",
				StartTime: startTime,
				EndTime:   endTime,
				Status:    failure,
				PluginStatus: []*plugin.Status{
					{
						Name:    "ext",
						Version: 2,
						Status:  failure,
					},
					{
						Name:    "det",
						Version: 3,
						Status:  failure,
					},
				},
			},
			want: &spb.ScanResult{
				Version:   "1.0.0",
				StartTime: timestamppb.New(startTime),
				EndTime:   timestamppb.New(endTime),
				Status:    failureProto,
				PluginStatus: []*spb.PluginStatus{
					{
						Name:    "ext",
						Version: 2,
						Status:  failureProto,
					},
					{
						Name:    "det",
						Version: 3,
						Status:  failureProto,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			if slices.Contains(tc.excludeForOS, runtime.GOOS) {
				t.Skipf("Skipping test %q on %s", tc.desc, runtime.GOOS)
			}

			got, err := proto.ScanResultToProto(tc.res)
			if err != tc.wantErr {
				t.Fatalf("proto.ScanResultToProto(%v) err: got %v, want %v", tc.res, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("check.Exec() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}
