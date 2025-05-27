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

package purl_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	apkmeta "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	cosmeta "github.com/google/osv-scalibr/extractor/filesystem/os/cos/metadata"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	flatpakmeta "github.com/google/osv-scalibr/extractor/filesystem/os/flatpak/metadata"
	modulemeta "github.com/google/osv-scalibr/extractor/filesystem/os/kernel/module/metadata"
	vmlinuzmeta "github.com/google/osv-scalibr/extractor/filesystem/os/kernel/vmlinuz/metadata"
	nixmeta "github.com/google/osv-scalibr/extractor/filesystem/os/nix/metadata"
	pacmanmeta "github.com/google/osv-scalibr/extractor/filesystem/os/pacman/metadata"
	portagemeta "github.com/google/osv-scalibr/extractor/filesystem/os/portage/metadata"
	ospurl "github.com/google/osv-scalibr/extractor/filesystem/os/purl"
	rpmmeta "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	snapmeta "github.com/google/osv-scalibr/extractor/filesystem/os/snap/metadata"
	"github.com/google/osv-scalibr/purl"
)

func TestMakePackageURLDebian(t *testing.T) {
	pkgname := "pkgname"
	sourcename := "sourcename"
	name := "name"
	version := "1.2.3"
	sourceversion := "1.2.4"
	source := "sourcename"
	tests := []struct {
		desc     string
		purlType string
		metadata *dpkgmeta.Metadata
		want     *purl.PackageURL
	}{
		{
			desc:     "both OS versions present",
			purlType: purl.TypeDebian,
			metadata: &dpkgmeta.Metadata{
				PackageName:       pkgname,
				SourceName:        sourcename,
				SourceVersion:     sourceversion,
				OSID:              "debian",
				OSVersionCodename: "jammy",
				OSVersionID:       "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeDebian,
				Name:      pkgname,
				Namespace: "debian",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Source:        source,
					purl.SourceVersion: sourceversion,
					purl.Distro:        "jammy",
				}),
			},
		},
		{
			desc:     "only VERSION_ID set",
			purlType: purl.TypeDebian,
			metadata: &dpkgmeta.Metadata{
				PackageName:   pkgname,
				SourceName:    sourcename,
				SourceVersion: sourceversion,
				OSID:          "debian",
				OSVersionID:   "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeDebian,
				Name:      pkgname,
				Namespace: "debian",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Source:        source,
					purl.SourceVersion: sourceversion,
					purl.Distro:        "22.04",
				}),
			},
		},
		{
			desc:     "ID not set, fallback to linux",
			purlType: purl.TypeDebian,
			metadata: &dpkgmeta.Metadata{
				PackageName:       pkgname,
				SourceName:        sourcename,
				SourceVersion:     sourceversion,
				OSVersionCodename: "jammy",
				OSVersionID:       "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeDebian,
				Name:      pkgname,
				Namespace: "linux",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Source:        source,
					purl.SourceVersion: sourceversion,
					purl.Distro:        "jammy",
				}),
			},
		},
		{
			desc:     "OS ID and OS Version set (OpenWrt)",
			purlType: purl.TypeOpkg,
			metadata: &dpkgmeta.Metadata{
				PackageName: pkgname,
				OSID:        "openwrt",
				OSVersionID: "22.03.5",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeOpkg,
				Name:      pkgname,
				Namespace: "openwrt",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "22.03.5",
				}),
			},
		},
		{
			desc:     "OS ID not set, fallback to linux",
			purlType: purl.TypeOpkg,
			metadata: &dpkgmeta.Metadata{
				PackageName:       pkgname,
				OSVersionCodename: "jammy",
				OSVersionID:       "5.10",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeOpkg,
				Name:      pkgname,
				Namespace: "linux",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "jammy",
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := ospurl.MakePackageURL(name, version, tt.purlType, tt.metadata)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ospurl.MakePackageURL(%v, %v, %v, %v): unexpected PURL (-want +got):\n%s", name, version, tt.purlType, tt.metadata, diff)
			}
		})
	}
}

func TestMakePackageURLFlatpak(t *testing.T) {
	pkgname := "pkgname"
	pkgid := "pkgid"
	pkgversion := "1.2.3"
	releasedate := "2024-05-02"
	osname := "Debian GNU/Linux"
	osid := "debian"
	osversionid := "12"
	osbuildid := "bookworm"
	developer := "developer"
	tests := []struct {
		desc     string
		metadata *flatpakmeta.Metadata
		want     *purl.PackageURL
	}{
		{
			desc: "Both VERSION_ID and BUILD_ID is set",
			metadata: &flatpakmeta.Metadata{
				PackageName:    pkgname,
				PackageID:      pkgid,
				PackageVersion: pkgversion,
				ReleaseDate:    releasedate,
				OSName:         osname,
				OSID:           osid,
				OSVersionID:    osversionid,
				OSBuildID:      osbuildid,
				Developer:      developer,
			},
			want: &purl.PackageURL{
				Type:      purl.TypeFlatpak,
				Name:      pkgname,
				Namespace: "debian",
				Version:   pkgversion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "debian-12",
				}),
			},
		},
		{
			desc: "only BUILD_ID set",
			metadata: &flatpakmeta.Metadata{
				PackageName:    pkgname,
				PackageID:      pkgid,
				PackageVersion: pkgversion,
				ReleaseDate:    releasedate,
				OSName:         osname,
				OSID:           osid,
				OSBuildID:      osbuildid,
				Developer:      developer,
			},
			want: &purl.PackageURL{
				Type:      purl.TypeFlatpak,
				Name:      pkgname,
				Namespace: "debian",
				Version:   pkgversion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "debian-bookworm",
				}),
			},
		},
		{
			desc: "OS_ID not set",
			metadata: &flatpakmeta.Metadata{
				PackageName:    pkgname,
				PackageID:      pkgid,
				PackageVersion: pkgversion,
				ReleaseDate:    releasedate,
				OSName:         osname,
				OSVersionID:    osversionid,
				OSBuildID:      osbuildid,
				Developer:      developer,
			},
			want: &purl.PackageURL{
				Type:      purl.TypeFlatpak,
				Name:      pkgname,
				Namespace: "",
				Version:   pkgversion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "12",
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := ospurl.MakePackageURL(pkgname, pkgversion, purl.TypeFlatpak, tt.metadata)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ospurl.MakePackageURL(%v, %v, %v, %v): unexpected PURL (-want +got):\n%s", pkgname, pkgversion, purl.TypeFlatpak, tt.metadata, diff)
			}
		})
	}
}

func TestMakePackageURLAPK(t *testing.T) {
	tests := []struct {
		desc     string
		metadata *apkmeta.Metadata
		want     *purl.PackageURL
	}{
		{
			desc: "all fields present",
			metadata: &apkmeta.Metadata{
				PackageName: "Name",
				OriginName:  "originName",
				OSID:        "id",
				OSVersionID: "4.5.6",
			},
			want: &purl.PackageURL{
				Type:       purl.TypeApk,
				Name:       "name",
				Namespace:  "id",
				Version:    "1.2.3",
				Qualifiers: purl.QualifiersFromMap(map[string]string{purl.Distro: "4.5.6", purl.Origin: "originName"}),
			},
		},
		{
			desc: "OS ID missing",
			metadata: &apkmeta.Metadata{
				PackageName: "Name",
				OriginName:  "originName",
				OSVersionID: "4.5.6",
			},
			want: &purl.PackageURL{
				Type:       purl.TypeApk,
				Name:       "name",
				Namespace:  "alpine",
				Version:    "1.2.3",
				Qualifiers: purl.QualifiersFromMap(map[string]string{purl.Distro: "4.5.6", purl.Origin: "originName"}),
			},
		},
		{
			desc: "OS version ID missing",
			metadata: &apkmeta.Metadata{
				PackageName: "Name",
				OriginName:  "originName",
				OSID:        "id",
			},
			want: &purl.PackageURL{
				Type:       purl.TypeApk,
				Name:       "name",
				Namespace:  "id",
				Version:    "1.2.3",
				Qualifiers: purl.QualifiersFromMap(map[string]string{purl.Origin: "originName"}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := ospurl.MakePackageURL("name", "1.2.3", purl.TypeApk, tt.metadata)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ospurl.MakePackageURL(%v): unexpected PURL (-want +got):\n%s", tt.metadata, diff)
			}
		})
	}
}

func TestMakePackageURLCOS(t *testing.T) {
	tests := []struct {
		desc     string
		metadata *cosmeta.Metadata
		want     *purl.PackageURL
	}{
		{
			desc: "both versions present",
			metadata: &cosmeta.Metadata{
				OSVersionID: "101",
				OSVersion:   "97",
			},
			want: &purl.PackageURL{
				Type:       purl.TypeCOS,
				Name:       "name",
				Version:    "1.2.3",
				Qualifiers: purl.QualifiersFromMap(map[string]string{purl.Distro: "cos-101"}),
			},
		},
		{
			desc: "only VERSION set",
			metadata: &cosmeta.Metadata{
				OSVersion: "97",
			},
			want: &purl.PackageURL{
				Type:       purl.TypeCOS,
				Name:       "name",
				Version:    "1.2.3",
				Qualifiers: purl.QualifiersFromMap(map[string]string{purl.Distro: "cos-97"}),
			},
		},
		{
			desc: "only VERSION_ID set",
			metadata: &cosmeta.Metadata{
				OSVersionID: "101",
			},
			want: &purl.PackageURL{
				Type:       purl.TypeCOS,
				Name:       "name",
				Version:    "1.2.3",
				Qualifiers: purl.QualifiersFromMap(map[string]string{purl.Distro: "cos-101"}),
			},
		},
		{
			desc:     "no versions set",
			metadata: &cosmeta.Metadata{},
			want: &purl.PackageURL{
				Type:       purl.TypeCOS,
				Name:       "name",
				Version:    "1.2.3",
				Qualifiers: purl.Qualifiers{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := ospurl.MakePackageURL("name", "1.2.3", purl.TypeCOS, tt.metadata)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ospurl.MakePackageURL(%v): unexpected PURL (-want +got):\n%s", tt.metadata, diff)
			}
		})
	}
}

func TestMakePackageURLRPM(t *testing.T) {
	pkgname := "pkgname"
	source := "source.rpm"
	version := "1.2.3"
	epoch := 1
	tests := []struct {
		desc     string
		metadata *rpmmeta.Metadata
		want     *purl.PackageURL
	}{
		{
			desc: "version ID and build ID present",
			metadata: &rpmmeta.Metadata{
				PackageName: pkgname,
				SourceRPM:   source,
				Epoch:       epoch,
				OSID:        "fedora",
				OSVersionID: "32",
				OSBuildID:   "asdf",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeRPM,
				Name:      pkgname,
				Namespace: "fedora",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Epoch:     "1",
					purl.Distro:    "fedora-32",
					purl.SourceRPM: source,
				}),
			},
		},
		{
			desc: "only build ID present",
			metadata: &rpmmeta.Metadata{
				PackageName: pkgname,
				SourceRPM:   source,
				Epoch:       epoch,
				OSID:        "fedora",
				OSBuildID:   "asdf",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeRPM,
				Name:      pkgname,
				Namespace: "fedora",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Epoch:     "1",
					purl.Distro:    "fedora-asdf",
					purl.SourceRPM: source,
				}),
			},
		},
		{
			desc: "ID missing",
			metadata: &rpmmeta.Metadata{
				PackageName: pkgname,
				SourceRPM:   source,
				Epoch:       epoch,
				OSVersionID: "32",
				OSBuildID:   "asdf",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeRPM,
				Name:      pkgname,
				Namespace: "",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Epoch:     "1",
					purl.Distro:    "32",
					purl.SourceRPM: source,
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := ospurl.MakePackageURL(pkgname, version, purl.TypeRPM, tt.metadata)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ospurl.MakePackageURL(%v): unexpected PURL (-want +got):\n%s", tt.metadata, diff)
			}
		})
	}
}

func TestMakePackageURLSnap(t *testing.T) {
	snapName := "testSnap"
	snapVersion := "1.2.3"
	snapGrade := "stable"
	snapType := "os"
	architectures := []string{"amd64", "arm64"}
	osID := "debian"
	osVersionCodename := "bookworm"
	osVersionID := "12"

	tests := []struct {
		desc     string
		metadata *snapmeta.Metadata
		want     *purl.PackageURL
	}{
		{
			desc: "Both VERSION_CODENAME and VERSION_ID are set",
			metadata: &snapmeta.Metadata{
				Name:              snapName,
				Version:           snapVersion,
				Grade:             snapGrade,
				Type:              snapType,
				Architectures:     architectures,
				OSID:              osID,
				OSVersionCodename: osVersionCodename,
				OSVersionID:       osVersionID,
			},
			want: &purl.PackageURL{
				Type:      purl.TypeSnap,
				Name:      snapName,
				Namespace: osID,
				Version:   snapVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: osVersionCodename,
				}),
			},
		},
		{
			desc: "Only VERSION_ID is set",
			metadata: &snapmeta.Metadata{
				Name:          snapName,
				Version:       snapVersion,
				Grade:         snapGrade,
				Type:          snapType,
				Architectures: architectures,
				OSID:          osID,
				OSVersionID:   osVersionID,
			},
			want: &purl.PackageURL{
				Type:      purl.TypeSnap,
				Name:      snapName,
				Namespace: osID,
				Version:   snapVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: osVersionID,
				}),
			},
		},
		{
			desc: "OSID, VERSION_CODENAME and VERSION_ID all are not set",
			metadata: &snapmeta.Metadata{
				Name:          snapName,
				Version:       snapVersion,
				Grade:         snapGrade,
				Type:          snapType,
				Architectures: architectures,
			},
			want: &purl.PackageURL{
				Type:       purl.TypeSnap,
				Name:       snapName,
				Namespace:  "",
				Version:    snapVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := ospurl.MakePackageURL(snapName, snapVersion, purl.TypeSnap, tt.metadata)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ospurl.MakePackageURL(%v): unexpected PURL (-want +got):\n%s", tt.metadata, diff)
			}
		})
	}
}

func TestMakePackageURLPacman(t *testing.T) {
	pkgName := "pkgName"
	pkgVersion := "pkgVersion"
	PackageDependencies := "pkgDependencies1, pkgDependencies2"

	tests := []struct {
		desc     string
		metadata *pacmanmeta.Metadata
		want     *purl.PackageURL
	}{
		{
			desc: "all fields present",
			metadata: &pacmanmeta.Metadata{
				PackageName:         pkgName,
				PackageVersion:      pkgVersion,
				OSID:                "arch",
				OSVersionID:         "20241201.0.284684",
				PackageDependencies: PackageDependencies,
			},
			want: &purl.PackageURL{
				Type:      purl.TypePacman,
				Name:      pkgName,
				Namespace: "arch",
				Version:   pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro:              "20241201.0.284684",
					purl.PackageDependencies: PackageDependencies,
				}),
			},
		},
		{
			desc: "only VERSION_ID set",
			metadata: &pacmanmeta.Metadata{
				PackageName:         pkgName,
				PackageVersion:      pkgVersion,
				OSID:                "arch",
				OSVersionID:         "20241201.0.284684",
				PackageDependencies: PackageDependencies,
			},
			want: &purl.PackageURL{
				Type:      purl.TypePacman,
				Name:      pkgName,
				Namespace: "arch",
				Version:   pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro:              "20241201.0.284684",
					purl.PackageDependencies: PackageDependencies,
				}),
			},
		},
		{
			desc: "OS ID not set, fallback to Linux",
			metadata: &pacmanmeta.Metadata{
				PackageName:         pkgName,
				PackageVersion:      pkgVersion,
				OSVersionID:         "20241201.0.284684",
				PackageDependencies: PackageDependencies,
			},
			want: &purl.PackageURL{
				Type:      purl.TypePacman,
				Name:      pkgName,
				Namespace: "linux",
				Version:   pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro:              "20241201.0.284684",
					purl.PackageDependencies: PackageDependencies,
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := ospurl.MakePackageURL(pkgName, pkgVersion, purl.TypePacman, tt.metadata)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ospurl.MakePackageURL(%v): unexpected PURL (-want +got):\n%s", tt.metadata, diff)
			}
		})
	}
}

func TestMakePackageURLPortage(t *testing.T) {
	pkgName := "pkgName"
	pkgVersion := "pkgVersion"

	tests := []struct {
		desc     string
		metadata *portagemeta.Metadata
		want     *purl.PackageURL
	}{
		{
			desc: "all fields present",
			metadata: &portagemeta.Metadata{
				PackageName:    pkgName,
				PackageVersion: pkgVersion,
				OSID:           "Gentoo",
				OSVersionID:    "20241201.0.284684",
			},
			want: &purl.PackageURL{
				Type:      purl.TypePortage,
				Name:      pkgName,
				Namespace: "Gentoo",
				Version:   pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "20241201.0.284684",
				}),
			},
		},
		{
			desc: "only VERSION_ID set",
			metadata: &portagemeta.Metadata{
				PackageName:    pkgName,
				PackageVersion: pkgVersion,
				OSID:           "linux",
				OSVersionID:    "2.17",
			},
			want: &purl.PackageURL{
				Type:      purl.TypePortage,
				Name:      pkgName,
				Namespace: "linux",
				Version:   pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "2.17",
				}),
			},
		},
		{
			desc: "ID not set, fallback to linux",
			metadata: &portagemeta.Metadata{
				PackageName:    pkgName,
				PackageVersion: pkgVersion,
				OSVersionID:    "jammy",
			},
			want: &purl.PackageURL{
				Type:      purl.TypePortage,
				Name:      pkgName,
				Namespace: "linux",
				Version:   pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "jammy",
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := ospurl.MakePackageURL(pkgName, pkgVersion, purl.TypePortage, tt.metadata)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ospurl.MakePackageURL(%v): unexpected PURL (-want +got):\n%s", tt.metadata, diff)
			}
		})
	}
}

func TestMakePackageURLNix(t *testing.T) {
	pkgName := "pkgName"
	pkgVersion := "pkgVersion"
	pkgHash := "pkgHash"
	pkgOutput := "pkgOutput"

	tests := []struct {
		desc     string
		metadata *nixmeta.Metadata
		want     *purl.PackageURL
	}{
		{
			desc: "all fields present",
			metadata: &nixmeta.Metadata{
				PackageName:       pkgName,
				PackageVersion:    pkgVersion,
				PackageHash:       pkgHash,
				PackageOutput:     pkgOutput,
				OSID:              "nixos",
				OSVersionCodename: "vicuna",
				OSVersionID:       "24.11",
			},
			want: &purl.PackageURL{
				Type:    purl.TypeNix,
				Name:    pkgName,
				Version: pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					"distro": "vicuna",
				}),
			},
		},
		{
			desc: "only VERSION_ID set",
			metadata: &nixmeta.Metadata{
				PackageName:    pkgName,
				PackageVersion: pkgVersion,
				PackageHash:    pkgHash,
				PackageOutput:  pkgOutput,
				OSID:           "nixos",
				OSVersionID:    "24.11",
			},
			want: &purl.PackageURL{
				Type:    purl.TypeNix,
				Name:    pkgName,
				Version: pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					"distro": "24.11",
				}),
			},
		},
		{
			desc: "OS ID not set, fallback to Nixos",
			metadata: &nixmeta.Metadata{
				PackageName:       pkgName,
				PackageVersion:    pkgVersion,
				PackageHash:       pkgHash,
				PackageOutput:     pkgOutput,
				OSVersionCodename: "vicuna",
				OSVersionID:       "24.11",
			},
			want: &purl.PackageURL{
				Type:    purl.TypeNix,
				Name:    pkgName,
				Version: pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					"distro": "vicuna",
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := ospurl.MakePackageURL(pkgName, pkgVersion, purl.TypeNix, tt.metadata)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ospurl.MakePackageURL(%v): unexpected PURL (-want +got):\n%s", tt.metadata, diff)
			}
		})
	}
}

func TestMakePackageURLVmlinuz(t *testing.T) {
	name := "Linux Kernel"
	version := "version"
	architecture := "architecture"
	extendedVersion := "extendedVersion"
	format := "format"
	swapDevice := int32(10)
	rootDevice := int32(11)
	videoMode := "videoMode"
	rwRootFS := true

	tests := []struct {
		desc     string
		metadata *vmlinuzmeta.Metadata
		want     *purl.PackageURL
	}{
		{
			desc: "all fields present",
			metadata: &vmlinuzmeta.Metadata{
				Name:              name,
				Version:           version,
				Architecture:      architecture,
				ExtendedVersion:   extendedVersion,
				Format:            format,
				SwapDevice:        swapDevice,
				RootDevice:        rootDevice,
				VideoMode:         videoMode,
				OSID:              "ubuntu",
				OSVersionCodename: "jammy",
				OSVersionID:       "22.04",
				RWRootFS:          rwRootFS,
			},
			want: &purl.PackageURL{
				Type:      purl.TypeKernelModule,
				Name:      name,
				Namespace: "ubuntu",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "22.04",
				}),
			},
		},
		{
			desc: "only VERSION_ID set",
			metadata: &vmlinuzmeta.Metadata{
				Name:            name,
				Version:         version,
				Architecture:    architecture,
				ExtendedVersion: extendedVersion,
				Format:          format,
				SwapDevice:      swapDevice,
				RootDevice:      rootDevice,
				VideoMode:       videoMode,
				OSID:            "ubuntu",
				OSVersionID:     "22.04",
				RWRootFS:        rwRootFS,
			},
			want: &purl.PackageURL{
				Type:      purl.TypeKernelModule,
				Name:      name,
				Namespace: "ubuntu",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "22.04",
				}),
			},
		},
		{
			desc: "OS ID not set, fallback to linux",
			metadata: &vmlinuzmeta.Metadata{
				Name:            name,
				Version:         version,
				Architecture:    architecture,
				ExtendedVersion: extendedVersion,
				Format:          format,
				SwapDevice:      swapDevice,
				RootDevice:      rootDevice,
				VideoMode:       videoMode,
				OSVersionID:     "22.04",
				RWRootFS:        rwRootFS,
			},
			want: &purl.PackageURL{
				Type:      purl.TypeKernelModule,
				Name:      name,
				Namespace: "linux",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "22.04",
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := ospurl.MakePackageURL(name, version, purl.TypeKernelModule, tt.metadata)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ospurl.MakePackageURL(%v): unexpected PURL (-want +got):\n%s", tt.metadata, diff)
			}
		})
	}
}

func TestMakePackageURLKernelModule(t *testing.T) {
	name := "name"
	version := "version"
	pkgVermagic := "pkgVermagic"
	packageSourceVersionIdentifier := "packageSourceVersionIdentifier"
	pkgAuthor := "pkgAuthor"

	tests := []struct {
		desc     string
		metadata *modulemeta.Metadata
		want     *purl.PackageURL
	}{
		{
			desc: "all fields present",
			metadata: &modulemeta.Metadata{
				PackageName:                    name,
				PackageVersion:                 version,
				PackageVermagic:                pkgVermagic,
				PackageSourceVersionIdentifier: packageSourceVersionIdentifier,
				PackageAuthor:                  pkgAuthor,
				OSID:                           "ubuntu",
				OSVersionCodename:              "jammy",
				OSVersionID:                    "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeKernelModule,
				Name:      name,
				Namespace: "ubuntu",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "22.04",
				}),
			},
		},
		{
			desc: "only VERSION_ID set",
			metadata: &modulemeta.Metadata{
				PackageName:                    name,
				PackageVersion:                 version,
				PackageVermagic:                pkgVermagic,
				PackageSourceVersionIdentifier: packageSourceVersionIdentifier,
				PackageAuthor:                  pkgAuthor,
				OSID:                           "ubuntu",
				OSVersionID:                    "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeKernelModule,
				Name:      name,
				Namespace: "ubuntu",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "22.04",
				}),
			},
		},
		{
			desc: "OS ID not set, fallback to linux",
			metadata: &modulemeta.Metadata{
				PackageName:                    name,
				PackageVersion:                 version,
				PackageVermagic:                pkgVermagic,
				PackageSourceVersionIdentifier: packageSourceVersionIdentifier,
				PackageAuthor:                  pkgAuthor,
				OSVersionID:                    "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeKernelModule,
				Name:      name,
				Namespace: "linux",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "22.04",
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := ospurl.MakePackageURL(name, version, purl.TypeKernelModule, tt.metadata)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ospurl.MakePackageURL(%v): unexpected PURL (-want +got):\n%s", tt.metadata, diff)
			}
		})
	}
}
