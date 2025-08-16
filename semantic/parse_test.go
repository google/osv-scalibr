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

package semantic_test

import (
	"errors"
	"testing"

	"github.com/google/osv-scalibr/semantic"
)

var ecosystems = []string{
	"AlmaLinux",
	"Alpaquita",
	"Alpine",
	"Bioconductor",
	"Bitnami",
	"Chainguard",
	"ConanCenter",
	"CRAN",
	"crates.io",
	"Debian",
	"Go",
	"Hex",
	"Mageia",
	"Maven",
	"MinimOS",
	"npm",
	"NuGet",
	"openEuler",
	"openSUSE",
	"Packagist",
	"Pub",
	"PyPI",
	"Rocky Linux",
	"RubyGems",
	"SUSE",
	"SwiftURL",
	"Ubuntu",
	"Wolfi",
}

func TestParse(t *testing.T) {
	for _, ecosystem := range ecosystems {
		_, err := semantic.Parse("", ecosystem)

		if errors.Is(err, semantic.ErrUnsupportedEcosystem) {
			t.Errorf("'%s' is not a supported ecosystem", ecosystem)
		}
	}
}

func TestParse_InvalidVersions(t *testing.T) {
	type args struct {
		versions  []string
		ecosystem string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "invalid_cran_versions",
			args: args{
				versions:  []string{"!", "?", "1.a.2", "z.c.3"},
				ecosystem: "CRAN",
			},
		},
		{
			name: "invalid_debian_versions",
			args: args{
				versions:  []string{"1.2.3-not-a-debian:version!@#$"},
				ecosystem: "Debian",
			},
		},
		{
			name: "invalid_hackage_versions",
			args: args{
				versions:  []string{"1.2.3.4.5-notallowed"},
				ecosystem: "Hackage",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, version := range tt.args.versions {
				_, err := semantic.Parse(version, tt.args.ecosystem)

				if err == nil {
					t.Errorf("expected error for '%s', got nil", version)

					continue
				}

				if !errors.Is(err, semantic.ErrInvalidVersion) {
					t.Errorf("expected ErrInvalidVersion for '%s', got '%v'", version, err)
				}
			}
		})
	}
}

func TestMustParse(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("unexpected panic - '%s'", r)
		}
	}()

	for _, ecosystem := range ecosystems {
		semantic.MustParse("", ecosystem)
	}
}

func TestMustParse_InvalidVersions(t *testing.T) {
	type args struct {
		versions  []string
		ecosystem string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "invalid_ecosystem",
			args: args{
				versions:  []string{""},
				ecosystem: "<unknown>",
			},
		},
		{
			name: "invalid_cran_versions",
			args: args{
				versions:  []string{"!", "?", "1.a.2", "z.c.3"},
				ecosystem: "CRAN",
			},
		},
		{
			name: "invalid_debian_versions",
			args: args{
				versions:  []string{"1.2.3-not-a-debian:version!@#$"},
				ecosystem: "Debian",
			},
		},
		{
			name: "invalid_hackage_versions",
			args: args{
				versions:  []string{"1.2.3.4.5-notallowed"},
				ecosystem: "Hackage",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("expected panic, got nil")
				}
			}()

			for _, version := range tt.args.versions {
				semantic.MustParse(version, tt.args.ecosystem)

				// if we reached here, then we can't have panicked
				t.Errorf("function did not panic when given invalid version '%s'", version)
			}
		})
	}
}
