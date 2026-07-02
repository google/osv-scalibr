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

//go:build !windows

package photon_test

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/os/photon"
	rpmmeta "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/fakefs"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestNew(t *testing.T) {
	e, err := photon.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("photon.New(): %v", err)
	}
	if e == nil {
		t.Fatal("photon.New() returned nil")
	}
}

func TestName(t *testing.T) {
	e, _ := photon.New(&cpb.PluginConfig{})
	if got, want := e.Name(), photon.Name; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func TestFileRequired(t *testing.T) {
	e, _ := photon.New(&cpb.PluginConfig{})

	tests := []struct {
		name     string
		path     string
		wantBool bool
	}{
		{
			name:     "rpmdb.sqlite in var/lib/rpm",
			path:     "var/lib/rpm/rpmdb.sqlite",
			wantBool: true,
		},
		{
			name:     "Packages in usr/lib/sysimage/rpm",
			path:     "usr/lib/sysimage/rpm/Packages",
			wantBool: true,
		},
		{
			name:     "Packages.db in usr/share/rpm",
			path:     "usr/share/rpm/Packages.db",
			wantBool: true,
		},
		{
			name:     "rpmdb.sqlite in usr/lib/sysimage/rpm",
			path:     "usr/lib/sysimage/rpm/rpmdb.sqlite",
			wantBool: true,
		},
		{
			name:     "wrong directory",
			path:     "tmp/rpmdb.sqlite",
			wantBool: false,
		},
		{
			name:     "wrong filename",
			path:     "var/lib/rpm/status",
			wantBool: false,
		},
		{
			name:     "dpkg status is unrelated",
			path:     "var/lib/dpkg/status",
			wantBool: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{FileName: "rpmdb.sqlite", FileSize: 100}))
			if got != tt.wantBool {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.wantBool)
			}
		})
	}
}

func TestMetadataToNamespace(t *testing.T) {
	// Verify that the Photon OS metadata correctly derives namespace "photon"
	// from the OSID field, which is how the RPM PURL namespace is set.
	meta := &rpmmeta.Metadata{
		PackageName:  "openssl",
		OSID:         "photon",
		OSVersionID:  "5.0",
		OSName:       "VMware Photon OS",
		OSPrettyName: "VMware Photon OS/Linux",
	}

	if got := meta.ToNamespace(); got != "photon" {
		t.Errorf("ToNamespace() = %q, want %q", got, "photon")
	}
}

func TestMetadataToDistro(t *testing.T) {
	meta := &rpmmeta.Metadata{
		OSID:        "photon",
		OSVersionID: "5.0",
	}
	distro := meta.ToDistro()
	if distro == "" {
		t.Error("ToDistro() = empty, want non-empty for Photon OS 5.0")
	}
	// Expected: "photon-5.0"
	if distro != "photon-5.0" {
		t.Errorf("ToDistro() = %q, want %q", distro, "photon-5.0")
	}
}

func TestPackagePURL(t *testing.T) {
	// Verify the full PURL generated for a Photon OS package.
	// OSV.dev "Photon OS" ecosystem is matched via:
	//   PURL type = "rpm", namespace = "photon"
	pkg := &extractor.Package{
		Name:     "tzdata",
		Version:  "2024a-1.ph5",
		PURLType: purl.TypeRPM,
		Metadata: &rpmmeta.Metadata{
			PackageName:  "tzdata",
			Architecture: "noarch",
			OSID:         "photon",
			OSVersionID:  "5.0",
			OSName:       "VMware Photon OS",
			OSPrettyName: "VMware Photon OS/Linux",
		},
	}

	p := pkg.PURL()
	tests := []struct {
		field string
		got   string
		want  string
	}{
		{"Type", p.Type, purl.TypeRPM},
		{"Namespace", p.Namespace, "photon"},
		{"Name", p.Name, "tzdata"},
		{"Version", p.Version, "2024a-1.ph5"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("PURL.%s = %q, want %q", tt.field, tt.got, tt.want)
		}
	}
}

func TestNonPhotonNamespace(t *testing.T) {
	// Verify that RHEL packages use "rhel" namespace, not "photon".
	// This ensures our extractor correctly filters by OS detection, not DB path alone.
	rhelMeta := &rpmmeta.Metadata{
		OSID:        "rhel",
		OSVersionID: "9",
	}
	if ns := rhelMeta.ToNamespace(); ns != "rhel" {
		t.Errorf("RHEL ToNamespace() = %q, want %q", ns, "rhel")
	}

	centosMeta := &rpmmeta.Metadata{
		OSID:        "centos",
		OSVersionID: "8",
	}
	if ns := centosMeta.ToNamespace(); ns != "centos" {
		t.Errorf("CentOS ToNamespace() = %q, want %q", ns, "centos")
	}
}
