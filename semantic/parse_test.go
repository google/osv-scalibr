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
	"GHC",
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

func TestParse_Debian_InvalidVersion(t *testing.T) {
	_, err := semantic.Parse("1.2.3-not-a-debian:version!@#$", "Debian")

	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if !errors.Is(err, semantic.ErrInvalidVersion) {
		t.Errorf("expected ErrInvalidVersion, got '%v'", err)
	}
}

func TestParse_Hackage_InvalidVersion(t *testing.T) {
	_, err := semantic.Parse("1.2.3.4.5-notallowed", "Hackage")

	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if !errors.Is(err, semantic.ErrInvalidVersion) {
		t.Errorf("expected ErrInvalidVersion, got '%v'", err)
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

func TestMustParse_Panic(t *testing.T) {
	defer func() { _ = recover() }()

	semantic.MustParse("", "<unknown>")

	// if we reached here, then we can't have panicked
	t.Errorf("function did not panic when given an unknown ecosystem")
}

func TestMustParse_Debian_InvalidVersion(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic, got nil")
		}
	}()

	semantic.MustParse("1.2.3-not-a-debian:version!@#$", "Debian")

	// if we reached here, then we can't have panicked
	t.Errorf("function did not panic when given an invalid version")
}

func TestMustParse_Hackage_InvalidVersion(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic, got nil")
		}
	}()

	semantic.MustParse("1.2.3.4.5-notallowed", "Hackage")

	// if we reached here, then we can't have panicked
	t.Errorf("function did not panic when given an invalid version")
}
