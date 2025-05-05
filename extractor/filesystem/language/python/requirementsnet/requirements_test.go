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

package requirementsnet_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/clients/clienttest"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirementsnet"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "basic",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/requirements.txt",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "alice",
					Version:   "1.0.0",
					Locations: []string{"testdata/requirements.txt"},
				},
				{
					Name:      "bob",
					Version:   "2.0.0",
					Locations: []string{"testdata/requirements.txt"},
				},
				{
					Name:      "chuck",
					Version:   "2.0.0",
					Locations: []string{"testdata/requirements.txt"},
				},
				{
					Name:      "dave",
					Version:   "2.0.0",
					Locations: []string{"testdata/requirements.txt"},
				},
				{
					Name:      "eve",
					Version:   "1.5.0",
					Locations: []string{"testdata/requirements.txt"},
				},
				{
					Name:      "frank",
					Version:   "2.0.0",
					Locations: []string{"testdata/requirements.txt"},
				},
			},
		},
		{
			// Copied from offline requirements extractor
			Name: "hash checking mode",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/hash-checking.txt",
			},
			WantPackages: []*extractor.Package{
				{
					// foo1==1.0 --hash=sha256:
					Name:      "foo1",
					Version:   "1.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/hash-checking.txt"},
					Metadata:  &requirements.Metadata{VersionComparator: "==", HashCheckingModeValues: []string{"sha256:123"}, Requirement: "foo1==1.0"},
				},
				{
					// foo2==1.0 --hash=sha256:123 --global-option=foo --config-settings=bar
					Name:      "foo2",
					Version:   "1.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/hash-checking.txt"},
					Metadata:  &requirements.Metadata{VersionComparator: "==", HashCheckingModeValues: []string{"sha256:123"}, Requirement: "foo2==1.0"},
				},
				{
					// foo3==1.0 --config-settings=bar --global-option=foo --hash=sha256:123
					Name:      "foo3",
					Version:   "1.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/hash-checking.txt"},
					Metadata:  &requirements.Metadata{VersionComparator: "==", HashCheckingModeValues: []string{"sha256:123"}, Requirement: "foo3==1.0"},
				},
				{
					// foo4==1.0 --hash=wrongformatbutok
					Name:      "foo4",
					Version:   "1.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/hash-checking.txt"},
					Metadata:  &requirements.Metadata{VersionComparator: "==", HashCheckingModeValues: []string{"wrongformatbutok"}, Requirement: "foo4==1.0"},
				},
				{
					// foo5==1.0; python_version < "2.7" --hash=sha256:123
					Name:      "foo5",
					Version:   "1.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/hash-checking.txt"},
					Metadata:  &requirements.Metadata{VersionComparator: "==", HashCheckingModeValues: []string{"sha256:123"}, Requirement: "foo5==1.0; python_version < \"2.7\""},
				},
				{
					// foo6==1.0 --hash=sha256:123 unexpected_text_after_first_option_does_not_stay_around --global-option=foo
					Name:      "foo6",
					Version:   "1.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/hash-checking.txt"},
					Metadata:  &requirements.Metadata{VersionComparator: "==", HashCheckingModeValues: []string{"sha256:123"}, Requirement: "foo6==1.0"},
				},
				{
					// foo7==1.0 unexpected_text_before_options_stays_around --hash=sha256:123
					Name:      "foo7",
					Version:   "1.0unexpected_text_before_options_stays_around",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/hash-checking.txt"},
					Metadata:  &requirements.Metadata{VersionComparator: "==", HashCheckingModeValues: []string{"sha256:123"}, Requirement: "foo7==1.0 unexpected_text_before_options_stays_around"},
				},
				{
					// foo8==1.0 --hash=sha256:123 --hash=sha256:456
					Name:      "foo8",
					Version:   "1.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/hash-checking.txt"},
					Metadata:  &requirements.Metadata{VersionComparator: "==", HashCheckingModeValues: []string{"sha256:123", "sha256:456"}, Requirement: "foo8==1.0"},
				},
				{
					// foo9==1.0 --hash=sha256:123 \
					// 	--hash=sha256:456
					Name:      "foo9",
					Version:   "1.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/hash-checking.txt"},
					Metadata:  &requirements.Metadata{VersionComparator: "==", HashCheckingModeValues: []string{"sha256:123", "sha256:456"}, Requirement: "foo9==1.0"},
				},
				// missing a version
				// foo10== --hash=sha256:123 --hash=sha256:123
				{
					// foo11==1.0 --hash=sha256:not_base16_encoded_is_ok_;#
					Name:      "foo11",
					Version:   "1.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/hash-checking.txt"},
					Metadata:  &requirements.Metadata{VersionComparator: "==", HashCheckingModeValues: []string{"sha256:not_base16_encoded_is_ok_;#"}, Requirement: "foo11==1.0"},
				},
				{
					// foo12==1.0 --hash=
					Name:      "foo12",
					Version:   "1.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/hash-checking.txt"},
					Metadata:  &requirements.Metadata{VersionComparator: "==", HashCheckingModeValues: []string{}, Requirement: "foo12==1.0"},
				},
				{
					// foo13==1.0 --hash sha256:123
					// The hash in this case is not recognized because it does not use an "=" separator
					// as specified by https://pip.pypa.io/en/stable/topics/secure-installs/#hash-checking-mode,
					// but it is dropped from the version.
					Name:      "foo13",
					Version:   "1.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/hash-checking.txt"},
					Metadata:  &requirements.Metadata{VersionComparator: "==", HashCheckingModeValues: []string{}, Requirement: "foo13==1.0"},
				},
				{
					// foo14=1.0 -C bar
					// short form for --config-settings flag, see https://pip.pypa.io/en/stable/cli/pip_install/#install-config-settings
					Name:      "foo14",
					Version:   "1.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/hash-checking.txt"},
					Metadata:  &requirements.Metadata{VersionComparator: "==", HashCheckingModeValues: []string{}, Requirement: "foo14==1.0"},
				},
				// Per the grammar in https://peps.python.org/pep-0508/#grammar, "--config-settings" may be
				// a valid version component, but such a string is not allowed as a version by
				// https://packaging.python.org/en/latest/specifications/version-specifiers/#version-specifiers.
				//
				// foo15== --config-settings --hash=sha256:123
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			resolutionClient := clienttest.NewMockResolutionClient(t, "testdata/basic-universe.yaml")
			extr := requirementsnet.New(requirementsnet.Config{
				Extractor: requirements.NewDefault().(*requirements.Extractor),
				Client:    resolutionClient,
			})

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(context.Background(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			wantInventory := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(wantInventory, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
