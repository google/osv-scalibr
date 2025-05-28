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

package proto_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/google/go-cmp/cmp"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/binary/proto"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/extractor"
	ctrdfs "github.com/google/osv-scalibr/extractor/filesystem/containers/containerd"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/podman"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/depsjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxmlnet"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/homebrew"
	"github.com/google/osv-scalibr/extractor/filesystem/os/nix"
	nixmeta "github.com/google/osv-scalibr/extractor/filesystem/os/nix/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/pacman"
	pacmanmeta "github.com/google/osv-scalibr/extractor/filesystem/os/pacman/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/portage"
	portagemeta "github.com/google/osv-scalibr/extractor/filesystem/os/portage/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpm"
	rpmmeta "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	cdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx/metadata"
	ctrdruntime "github.com/google/osv-scalibr/extractor/standalone/containers/containerd"
	"github.com/google/osv-scalibr/extractor/standalone/containers/docker"
	winmetadata "github.com/google/osv-scalibr/extractor/standalone/windows/common/metadata"
	"github.com/google/osv-scalibr/extractor/standalone/windows/dismpatch"
	"github.com/google/osv-scalibr/inventory"
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
	purlDPKGPackage := &extractor.Package{
		Name:     "software",
		Version:  "1.0.0",
		PURLType: purl.TypeDebian,
		Metadata: &dpkgmeta.Metadata{
			PackageName:       "software",
			PackageVersion:    "1.0.0",
			OSID:              "debian",
			OSVersionCodename: "jammy",
			Maintainer:        "maintainer",
			Architecture:      "amd64",
		},
		Locations: []string{"/file1"},
		Plugins:   []string{dpkg.Name},
	}
	purlDPKGAnnotationPackage := &extractor.Package{
		Name:     "software",
		Version:  "1.0.0",
		PURLType: purl.TypeDebian,
		Metadata: &dpkgmeta.Metadata{
			PackageName:       "software",
			PackageVersion:    "1.0.0",
			OSID:              "debian",
			OSVersionCodename: "jammy",
			Maintainer:        "maintainer",
			Architecture:      "amd64",
		},
		Locations:   []string{"/file1"},
		Plugins:     []string{dpkg.Name},
		Annotations: []extractor.Annotation{extractor.Transitional},
	}
	purlPythonPackage := &extractor.Package{
		Name:      "software",
		Version:   "1.0.0",
		PURLType:  purl.TypePyPi,
		Locations: []string{"/file1"},
		Plugins:   []string{wheelegg.Name},
		Metadata: &wheelegg.PythonPackageMetadata{
			Author:      "author",
			AuthorEmail: "author@corp.com",
		},
	}
	pythonRequirementsPackage := &extractor.Package{
		Name:      "foo",
		Version:   "1.0",
		PURLType:  purl.TypePyPi,
		Locations: []string{"/file1"},
		Plugins:   []string{requirements.Name},
		Metadata: &requirements.Metadata{
			HashCheckingModeValues: []string{"sha256:123"},
			VersionComparator:      ">=",
			Requirement:            "foo>=1.0",
		},
	}
	purlJavascriptPackage := &extractor.Package{
		Name:     "software",
		Version:  "1.0.0",
		PURLType: purl.TypeNPM,
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
		Plugins:   []string{packagejson.Name},
	}

	purlDotnetDepsJSONPackage := &extractor.Package{
		Name:     "software",
		Version:  "1.0.0",
		PURLType: purl.TypeNuget,
		Metadata: &depsjson.Metadata{
			PackageName:    "software",
			PackageVersion: "1.0.0",
			Type:           "type",
		},
		Locations: []string{"/file1"},
		Plugins:   []string{depsjson.Name},
	}

	purlDotnetDepsJSONPackageProto := &spb.Package{
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
		Plugins:   []string{"dotnet/depsjson"},
		Metadata: &spb.Package_DepsjsonMetadata{
			DepsjsonMetadata: &spb.DEPSJSONMetadata{
				PackageName:    "software",
				PackageVersion: "1.0.0",
				Type:           "type",
			},
		},
	}

	windowsPackage := &extractor.Package{
		Name:     "windows_server_2019",
		Version:  "10.0.17763.3406",
		PURLType: "windows",
		Metadata: &winmetadata.OSVersion{
			Product:     "windows_server_2019",
			FullVersion: "10.0.17763.3406",
		},
		Plugins: []string{dismpatch.Name},
	}

	purlDPKGPackageProto := &spb.Package{
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
		Metadata: &spb.Package_DpkgMetadata{
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
		Plugins:   []string{"os/dpkg"},
	}
	purlDPKGAnnotationPackageProto := &spb.Package{
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
		Metadata: &spb.Package_DpkgMetadata{
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
		Plugins:     []string{"os/dpkg"},
		Annotations: []spb.Package_AnnotationEnum{spb.Package_TRANSITIONAL},
	}
	purlPythonPackageProto := &spb.Package{
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
		Plugins:   []string{"python/wheelegg"},
		Metadata: &spb.Package_PythonMetadata{
			PythonMetadata: &spb.PythonPackageMetadata{
				Author:      "author",
				AuthorEmail: "author@corp.com",
			},
		},
	}
	pythonRequirementsPackageProto := &spb.Package{
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
		Plugins:   []string{"python/requirements"},
		Metadata: &spb.Package_PythonRequirementsMetadata{
			PythonRequirementsMetadata: &spb.PythonRequirementsMetadata{
				HashCheckingModeValues: []string{"sha256:123"},
				VersionComparator:      ">=",
				Requirement:            "foo>=1.0",
			},
		},
	}
	purlJavascriptPackageProto := &spb.Package{
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
		Plugins:   []string{"javascript/packagejson"},
		Metadata: &spb.Package_JavascriptMetadata{
			JavascriptMetadata: &spb.JavascriptPackageJSONMetadata{
				Maintainers: []string{
					"maintainer1 <maintainer1@corp.com> (https://blog.maintainer1.com)",
					"maintainer2 <maintainer2@corp.com>",
				},
			},
		},
	}
	cdxPackage := &extractor.Package{
		Name:     "openssl",
		Version:  "1.1.1",
		PURLType: purl.TypeNPM,
		Metadata: &cdxmeta.Metadata{
			PURL: &purl.PackageURL{
				Type:    purl.TypeNPM,
				Name:    "openssl",
				Version: "1.1.1",
			},
		},
		Locations: []string{"/openssl"},
		Plugins:   []string{cdx.Name},
	}
	cdxPackageProto := &spb.Package{
		Name:      "openssl",
		Version:   "1.1.1",
		Ecosystem: "npm",
		Purl: &spb.Purl{
			Purl:    "pkg:npm/openssl@1.1.1",
			Type:    purl.TypeNPM,
			Name:    "openssl",
			Version: "1.1.1",
		},
		Metadata: &spb.Package_CdxMetadata{
			CdxMetadata: &spb.CDXPackageMetadata{
				Purl: &spb.Purl{
					Purl:    "pkg:npm/openssl@1.1.1",
					Type:    purl.TypeNPM,
					Name:    "openssl",
					Version: "1.1.1",
				},
			},
		},
		Locations: []string{"/openssl"},
		Plugins:   []string{"sbom/cdx"},
	}
	purlRPMPackage := &extractor.Package{
		Name:     "openssh-clients",
		Version:  "5.3p1",
		PURLType: purl.TypeRPM,
		Metadata: &rpmmeta.Metadata{
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
		Plugins:   []string{rpm.Name},
	}
	purlRPMPackageProto := &spb.Package{
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
		Metadata: &spb.Package_RpmMetadata{
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
		Plugins:   []string{"os/rpm"},
	}
	purlPACMANPackage := &extractor.Package{
		Name:     "zstd",
		Version:  "1.5.6-1",
		PURLType: purl.TypePacman,
		Metadata: &pacmanmeta.Metadata{
			PackageName:    "zstd",
			PackageVersion: "1.5.6-1",
			OSID:           "arch",
			OSVersionID:    "20241201.0.284684",
		},
		Locations: []string{"/file1"},
		Plugins:   []string{pacman.Name},
	}
	purlPACMANPackageProto := &spb.Package{
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
		Metadata: &spb.Package_PacmanMetadata{
			PacmanMetadata: &spb.PACMANPackageMetadata{
				PackageName:    "zstd",
				PackageVersion: "1.5.6-1",
				OsId:           "arch",
				OsVersionId:    "20241201.0.284684",
			},
		},
		Locations: []string{"/file1"},
		Plugins:   []string{"os/pacman"},
	}
	purlPORTAGEPackage := &extractor.Package{
		Name:     "Capture-Tiny",
		Version:  "0.480.0-r1",
		PURLType: purl.TypePortage,
		Metadata: &portagemeta.Metadata{
			PackageName:    "Capture-Tiny",
			PackageVersion: "0.480.0-r1",
			OSID:           "gentoo",
			OSVersionID:    "2.17",
		},
		Locations: []string{"/file1"},
		Plugins:   []string{portage.Name},
	}
	purlPORTAGEPackageProto := &spb.Package{
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
		Metadata: &spb.Package_PortageMetadata{
			PortageMetadata: &spb.PortagePackageMetadata{
				PackageName:    "Capture-Tiny",
				PackageVersion: "0.480.0-r1",
				OsId:           "gentoo",
				OsVersionId:    "2.17",
			},
		},
		Locations: []string{"/file1"},
		Plugins:   []string{"os/portage"},
	}
	purlNixPackage := &extractor.Package{
		Name:     "attr",
		Version:  "2.5.2",
		PURLType: purl.TypeNix,
		Metadata: &nixmeta.Metadata{
			PackageName:       "attr",
			PackageVersion:    "2.5.2",
			OSID:              "nixos",
			OSVersionCodename: "vicuna",
			OSVersionID:       "24.11",
		},
		Locations: []string{"/file1"},
		Plugins:   []string{nix.Name},
	}
	purlNixPackageProto := &spb.Package{
		Name:    "attr",
		Version: "2.5.2",
		Purl: &spb.Purl{
			Purl:    "pkg:nix/attr@2.5.2?distro=vicuna",
			Type:    purl.TypeNix,
			Name:    "attr",
			Version: "2.5.2",
			Qualifiers: []*spb.Qualifier{
				{Key: "distro", Value: "vicuna"},
			},
		},
		Ecosystem: "",
		Metadata: &spb.Package_NixMetadata{
			NixMetadata: &spb.NixPackageMetadata{
				PackageName:       "attr",
				PackageVersion:    "2.5.2",
				OsId:              "nixos",
				OsVersionCodename: "vicuna",
				OsVersionId:       "24.11",
			},
		},
		Locations: []string{"/file1"},
		Plugins:   []string{"os/nix"},
	}
	purlHomebrewPackage := &extractor.Package{
		Name:      "rclone",
		Version:   "1.67.0",
		PURLType:  purl.TypeBrew,
		Metadata:  &homebrew.Metadata{},
		Locations: []string{"/file1"},
		Plugins:   []string{homebrew.Name},
	}
	purlHomebrewPackageProto := &spb.Package{
		Name:    "rclone",
		Version: "1.67.0",
		Purl: &spb.Purl{
			Purl:    "pkg:brew/rclone@1.67.0",
			Type:    purl.TypeBrew,
			Name:    "rclone",
			Version: "1.67.0",
		},
		Metadata:  &spb.Package_HomebrewMetadata{},
		Locations: []string{"/file1"},
		Plugins:   []string{"os/homebrew"},
	}
	containerdPackage := &extractor.Package{
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
		Plugins:   []string{ctrdfs.Name},
	}
	containerdPackageProto := &spb.Package{
		Name:      "gcr.io/google-samples/hello-app:1.0",
		Version:   "sha256:b1455e1c4fcc5ea1023c9e3b584cd84b64eb920e332feff690a2829696e379e7",
		Ecosystem: "",
		Metadata: &spb.Package_ContainerdContainerMetadata{
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
		Plugins:   []string{"containers/containerd"},
	}
	containerdRuntimePackage := &extractor.Package{
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
		Plugins:   []string{ctrdruntime.Name},
	}
	containerdRuntimePackageProto := &spb.Package{
		Name:      "gcr.io/google-samples/hello-app:1.0",
		Version:   "sha256:b1455e1c4fcc5ea1023c9e3b584cd84b64eb920e332feff690a2829696e379e7",
		Ecosystem: "",
		Metadata: &spb.Package_ContainerdRuntimeContainerMetadata{
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
		Plugins:   []string{"containers/containerd-runtime"},
	}
	windowsPackageProto := &spb.Package{
		Name:    "windows_server_2019",
		Version: "10.0.17763.3406",
		Metadata: &spb.Package_WindowsOsVersionMetadata{
			WindowsOsVersionMetadata: &spb.WindowsOSVersion{
				Product:     "windows_server_2019",
				FullVersion: "10.0.17763.3406",
			},
		},
		Purl: &spb.Purl{
			Purl:      "pkg:generic/microsoft/windows_server_2019@10.0.17763.3406?buildnumber=10.0.17763.3406",
			Type:      purl.TypeGeneric,
			Namespace: "microsoft",
			Name:      "windows_server_2019",
			Version:   "10.0.17763.3406",
			Qualifiers: []*spb.Qualifier{
				{
					Key:   "buildnumber",
					Value: "10.0.17763.3406",
				},
			},
		},
		Plugins: []string{"windows/dismpatch"},
	}
	purlPythonPackageWithLayerDetails := &extractor.Package{
		Name:      "software",
		Version:   "1.0.0",
		PURLType:  purl.TypePyPi,
		Locations: []string{"/file1"},
		Plugins:   []string{wheelegg.Name},
		Metadata: &wheelegg.PythonPackageMetadata{
			Author:      "author",
			AuthorEmail: "author@corp.com",
		},
		LayerDetails: &extractor.LayerDetails{
			Index:       0,
			DiffID:      "hash1",
			ChainID:     "chainid1",
			Command:     "command1",
			InBaseImage: true,
		},
	}
	purlPythonPackageWithLayerDetailsProto := &spb.Package{
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
		Plugins:   []string{"python/wheelegg"},
		Metadata: &spb.Package_PythonMetadata{
			PythonMetadata: &spb.PythonPackageMetadata{
				Author:      "author",
				AuthorEmail: "author@corp.com",
			},
		},
		LayerDetails: &spb.LayerDetails{
			Index:       0,
			DiffId:      "hash1",
			ChainId:     "chainid1",
			Command:     "command1",
			InBaseImage: true,
		},
	}
	mavenPackage := &extractor.Package{
		Name:      "abc:xyz",
		Version:   "1.0.0",
		PURLType:  purl.TypeMaven,
		Locations: []string{"/pom.xml"},
		Plugins:   []string{pomxmlnet.Name},
		Metadata: &javalockfile.Metadata{
			GroupID:      "abc",
			ArtifactID:   "xyz",
			IsTransitive: true,
		},
	}
	mavenPackageProto := &spb.Package{
		Name:      "abc:xyz",
		Version:   "1.0.0",
		Ecosystem: "Maven",
		Purl: &spb.Purl{
			Purl:      "pkg:maven/abc/xyz@1.0.0",
			Type:      purl.TypeMaven,
			Name:      "xyz",
			Namespace: "abc",
			Version:   "1.0.0",
		},
		Locations: []string{"/pom.xml"},
		Plugins:   []string{"java/pomxmlnet"},
		Metadata: &spb.Package_JavaLockfileMetadata{
			JavaLockfileMetadata: &spb.JavaLockfileMetadata{
				ArtifactId:   "xyz",
				GroupId:      "abc",
				IsTransitive: true,
			},
		},
	}

	podmanPackage := &extractor.Package{
		Name:    "docker.io/redis",
		Version: "a8036f14f15ead9517115576fb4462894a000620c2be556410f6c24afb8a482b",
		Metadata: &podman.Metadata{
			ExposedPorts: map[uint16][]string{6379: {"tcp"}},
			PID:          4232,
			Status:       "running",
			NameSpace:    "",
			StartedTime:  endTime.Add(-10 * time.Minute),
			FinishedTime: endTime.Add(-5 * time.Minute),
			ExitCode:     0,
			Exited:       false,
		},
		Plugins: []string{podman.Name},
	}
	podmanPackageProto := &spb.Package{
		Name:    "docker.io/redis",
		Version: "a8036f14f15ead9517115576fb4462894a000620c2be556410f6c24afb8a482b",
		Metadata: &spb.Package_PodmanMetadata{
			PodmanMetadata: &spb.PodmanMetadata{
				ExposedPorts:  map[uint32]*spb.Protocol{6379: {Names: []string{"tcp"}}},
				Pid:           4232,
				NamespaceName: "",
				StartedTime:   timestamppb.New(endTime.Add(-10 * time.Minute)),
				FinishedTime:  timestamppb.New(endTime.Add(-5 * time.Minute)),
				Status:        "running",
				ExitCode:      0,
				Exited:        false,
			},
		},
		Plugins: []string{"containers/podman"},
	}

	dockerPackage := &extractor.Package{
		Name:    "redis",
		Version: "sha256:a8036f14f15ead9517115576fb4462894a000620c2be556410f6c24afb8a482b",
		Metadata: &docker.Metadata{
			ImageName:   "redis",
			ImageDigest: "sha256:a8036f14f15ead9517115576fb4462894a000620c2be556410f6c24afb8a482b",
			ID:          "3ea6adad2e94daf386e1d6c5960807b41f19da2333e8a6261065c1cb8e85ac81",
			Ports:       []container.Port{{IP: "127.0.0.1", PrivatePort: 6379, PublicPort: 1112, Type: "tcp"}},
		},
		Plugins: []string{docker.Name},
	}

	dockerPackageProto := &spb.Package{
		Name:    "redis",
		Version: "sha256:a8036f14f15ead9517115576fb4462894a000620c2be556410f6c24afb8a482b",
		Metadata: &spb.Package_DockerContainersMetadata{
			DockerContainersMetadata: &spb.DockerContainersMetadata{
				ImageName:   "redis",
				ImageDigest: "sha256:a8036f14f15ead9517115576fb4462894a000620c2be556410f6c24afb8a482b",
				Id:          "3ea6adad2e94daf386e1d6c5960807b41f19da2333e8a6261065c1cb8e85ac81",
				Ports: []*spb.DockerPort{
					{Ip: "127.0.0.1", PrivatePort: 6379, PublicPort: 1112, Type: "tcp"},
				},
			},
		},
		Plugins: []string{"containers/docker"},
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
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{
						purlDPKGPackage,
						purlDPKGAnnotationPackage,
						purlPythonPackage,
						pythonRequirementsPackage,
						purlJavascriptPackage,
						purlDotnetDepsJSONPackage,
						cdxPackage,
						windowsPackage,
						purlPythonPackageWithLayerDetails,
						purlHomebrewPackage,
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
								Location: []string{"/file2"},
								Package:  purlDPKGPackage,
							},
							Extra: "extra details",
						},
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
				Inventory: &spb.Inventory{
					Packages: []*spb.Package{
						purlDPKGPackageProto,
						purlDPKGAnnotationPackageProto,
						purlPythonPackageProto,
						pythonRequirementsPackageProto,
						purlJavascriptPackageProto,
						purlDotnetDepsJSONPackageProto,
						cdxPackageProto,
						windowsPackageProto,
						purlPythonPackageWithLayerDetailsProto,
						purlHomebrewPackageProto,
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
								Location: []string{"/file2"},
								Package:  purlDPKGPackageProto,
							},
							Extra: "extra details",
						},
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
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{purlRPMPackage},
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
				},
				Inventory: &spb.Inventory{
					Packages: []*spb.Package{purlRPMPackageProto},
					Findings: []*spb.Finding{},
				},
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
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{purlPACMANPackage},
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
				},
				Inventory: &spb.Inventory{
					Packages: []*spb.Package{purlPACMANPackageProto},
					Findings: []*spb.Finding{},
				},
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
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{purlPORTAGEPackage},
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
				},
				Inventory: &spb.Inventory{
					Packages: []*spb.Package{purlPORTAGEPackageProto},
					Findings: []*spb.Finding{},
				},
			},
			excludeForOS: []string{"windows", "darwin"},
		},
		{
			desc: "Successful Nix scan linux-only",
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
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{purlNixPackage},
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
				},
				Inventory: &spb.Inventory{
					Packages: []*spb.Package{purlNixPackageProto},
					Findings: []*spb.Finding{},
				},
			},
			excludeForOS: []string{"windows", "darwin"},
		},
		{
			desc: "Successful Homebrew scan darwin-only",
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
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{purlHomebrewPackage},
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
				},
				Inventory: &spb.Inventory{
					Packages: []*spb.Package{purlHomebrewPackageProto},
					Findings: []*spb.Finding{},
				},
			},
			excludeForOS: []string{"windows", "linux"},
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
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{containerdPackage},
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
				},
				Inventory: &spb.Inventory{
					Packages: []*spb.Package{containerdPackageProto},
					Findings: []*spb.Finding{},
				},
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
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{containerdRuntimePackage},
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
				},
				Inventory: &spb.Inventory{
					Packages: []*spb.Package{containerdRuntimePackageProto},
					Findings: []*spb.Finding{},
				},
			},
			// TODO(b/349138656): Remove windows from this exclusion when containerd is supported
			// on Windows.
			excludeForOS: []string{"windows", "darwin"},
		},
		{
			desc: "Successful docker scan",
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
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{dockerPackage},
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
				},
				Inventory: &spb.Inventory{
					Packages: []*spb.Package{dockerPackageProto},
					Findings: []*spb.Finding{},
				},
			},
		},
		{
			desc: "Successful podman runtime scan linux-only",
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
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{podmanPackage},
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
				},
				Inventory: &spb.Inventory{
					Packages: []*spb.Package{podmanPackageProto},
					Findings: []*spb.Finding{},
				},
			},
			excludeForOS: []string{"windows", "darwin"},
		},
		{
			desc: "no package target, still works",
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
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{purlDPKGPackage, purlPythonPackage, purlJavascriptPackage, cdxPackage},
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
				Inventory: &spb.Inventory{
					Packages: []*spb.Package{purlDPKGPackageProto, purlPythonPackageProto, purlJavascriptPackageProto, cdxPackageProto},
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
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{purlDPKGPackage, purlPythonPackage, purlJavascriptPackage, cdxPackage},
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
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{purlDPKGPackage, purlPythonPackage, purlJavascriptPackage, cdxPackage},
					Findings: []*detector.Finding{
						{
							Extra: "extra details",
						},
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
				Inventory: &spb.Inventory{},
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
		{
			desc: "pom.xml inventories with transitive dependencies",
			res: &scalibr.ScanResult{
				Version:   "1.0.0",
				StartTime: startTime,
				EndTime:   endTime,
				Status:    success,
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{mavenPackage},
				},
			},
			want: &spb.ScanResult{
				Version:   "1.0.0",
				StartTime: timestamppb.New(startTime),
				EndTime:   timestamppb.New(endTime),
				Status:    successProto,
				Inventory: &spb.Inventory{
					Packages: []*spb.Package{mavenPackageProto},
					Findings: []*spb.Finding{},
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
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("proto.ScanResultToProto(%v) err: got %v, want %v", tc.res, err, tc.wantErr)
			}

			// Ignore deprecated fields in the comparison.
			// TODO(b/400910349): Stop setting the deprecated fields
			// once integrators no longer read them.
			if got != nil {
				//nolint:staticcheck
				got.InventoriesDeprecated = nil
				//nolint:staticcheck
				got.FindingsDeprecated = nil
				for _, p := range got.Inventory.Packages {
					//nolint:staticcheck
					p.ExtractorDeprecated = ""
				}
				for _, f := range got.Inventory.Findings {
					if f.Target != nil && f.Target.Package != nil {
						//nolint:staticcheck
						f.Target.Package.ExtractorDeprecated = ""
					}
				}
			}

			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("check.Exec() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}
