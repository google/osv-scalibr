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

package rpm_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-cpy/cpy"
	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/osduplicate/rpm"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/testing/fakefs"
	"google.golang.org/protobuf/proto"
)

func TestAnnotate(t *testing.T) {
	// if runtime.GOOS != "linux" {
	// 	t.Skipf("Test skipped, OS unsupported: %v", runtime.GOOS)
	// }

	cancelledContext, cancel := context.WithCancel(t.Context())
	cancel()

	copier := cpy.New(
		cpy.Func(proto.Clone),
		cpy.IgnoreAllUnexported(),
	)

	tests := []struct {
		desc     string
		packages []*extractor.Package
		fakeFS   string
		//nolint:containedctx
		ctx          context.Context
		wantErr      error
		wantPackages []*extractor.Package
	}{
		{
			desc: "no_rpm_dbs",
			packages: []*extractor.Package{
				{
					Name:     "pyxattr",
					Location: extractor.LocationFromPath("usr/lib64/python2.7/site-packages/pyxattr-0.5.1-py2.7.egg-info"),
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "pyxattr",
					Location: extractor.LocationFromPath("usr/lib64/python2.7/site-packages/pyxattr-0.5.1-py2.7.egg-info"),
				},
			},
		},
		{
			desc: "some_pkgs_found_in_Packages",
			fakeFS: `
-- usr/lib/sysimage/rpm/Packages --
-> testdata/Packages
`,
			packages: []*extractor.Package{
				{
					Name:     "pyxattr",
					Location: extractor.LocationFromPath("usr/lib64/python2.7/site-packages/pyxattr-0.5.1-py2.7.egg-info"),
				},
				{
					Name:     "not-in-db",
					Location: extractor.LocationFromPath("path/not/in/db"),
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "pyxattr",
					Location: extractor.LocationFromPath("usr/lib64/python2.7/site-packages/pyxattr-0.5.1-py2.7.egg-info"),
					ExploitabilitySignals: []*vex.PackageExploitabilitySignal{&vex.PackageExploitabilitySignal{
						Plugin:          rpm.Name,
						Justification:   vex.ComponentNotPresent,
						MatchesAllVulns: true,
					}},
				},
				{
					Name:     "not-in-db",
					Location: extractor.LocationFromPath("path/not/in/db"),
				},
			},
		},
		{
			desc: "some_pkg_found_in_Packages.db",
			fakeFS: `
-- var/lib/rpm/Packages.db --
-> testdata/Packages.db
`,
			packages: []*extractor.Package{
				{
					Name:     "cracklib",
					Location: extractor.LocationFromPath("usr/sbin/cracklib-check"),
				},
				{
					Name:     "not-in-db",
					Location: extractor.LocationFromPath("path/not/in/db"),
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "cracklib",
					Location: extractor.LocationFromPath("usr/sbin/cracklib-check"),
					ExploitabilitySignals: []*vex.PackageExploitabilitySignal{&vex.PackageExploitabilitySignal{
						Plugin:          rpm.Name,
						Justification:   vex.ComponentNotPresent,
						MatchesAllVulns: true,
					}},
				},
				{
					Name:     "not-in-db",
					Location: extractor.LocationFromPath("path/not/in/db"),
				},
			},
		},
		{
			desc: "some_pkg_found_in_rpmdb.sqlite",
			fakeFS: `
-- usr/share/rpm/rpmdb.sqlite --
-> testdata/rpmdb.sqlite
`,
			packages: []*extractor.Package{
				{
					Name:     "python3-gpg",
					Location: extractor.LocationFromPath("usr/lib64/python3.9/site-packages/gpg-1.15.1-py3.9.egg-info"),
				},
				{
					Name:     "not-in-db",
					Location: extractor.LocationFromPath("path/not/in/db"),
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "python3-gpg",
					Location: extractor.LocationFromPath("usr/lib64/python3.9/site-packages/gpg-1.15.1-py3.9.egg-info"),
					ExploitabilitySignals: []*vex.PackageExploitabilitySignal{&vex.PackageExploitabilitySignal{
						Plugin:          rpm.Name,
						Justification:   vex.ComponentNotPresent,
						MatchesAllVulns: true,
					}},
				},
				{
					Name:     "not-in-db",
					Location: extractor.LocationFromPath("path/not/in/db"),
				},
			},
		},
		{
			desc: "some_pkg_found_in_multiple_dbs",
			fakeFS: `
-- var/lib/rpm/Packages --
-> testdata/Packages
-- usr/lib/sysimage/rpm/Packages.db --
-> testdata/Packages.db
-- usr/lib/sysimage/rpm/rpmdb.sqlite --
-> testdata/rpmdb.sqlite
`,
			packages: []*extractor.Package{
				{
					// From Packages
					Name:     "pyxattr",
					Location: extractor.LocationFromPath("usr/lib64/python2.7/site-packages/pyxattr-0.5.1-py2.7.egg-info"),
				},
				{
					// From Packages.db
					Name:     "cracklib",
					Location: extractor.LocationFromPath("usr/sbin/cracklib-check"),
				},
				{
					// From rpmdb.sqlite
					Name:     "python3-gpg",
					Location: extractor.LocationFromPath("usr/lib64/python3.9/site-packages/gpg-1.15.1-py3.9.egg-info"),
				},
				{
					Name:     "not-in-db",
					Location: extractor.LocationFromPath("path/not/in/db"),
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "pyxattr",
					Location: extractor.LocationFromPath("usr/lib64/python2.7/site-packages/pyxattr-0.5.1-py2.7.egg-info"),
					ExploitabilitySignals: []*vex.PackageExploitabilitySignal{&vex.PackageExploitabilitySignal{
						Plugin:          rpm.Name,
						Justification:   vex.ComponentNotPresent,
						MatchesAllVulns: true,
					}},
				},
				{
					Name:     "cracklib",
					Location: extractor.LocationFromPath("usr/sbin/cracklib-check"),
					ExploitabilitySignals: []*vex.PackageExploitabilitySignal{&vex.PackageExploitabilitySignal{
						Plugin:          rpm.Name,
						Justification:   vex.ComponentNotPresent,
						MatchesAllVulns: true,
					}},
				},
				{
					Name:     "python3-gpg",
					Location: extractor.LocationFromPath("usr/lib64/python3.9/site-packages/gpg-1.15.1-py3.9.egg-info"),
					ExploitabilitySignals: []*vex.PackageExploitabilitySignal{&vex.PackageExploitabilitySignal{
						Plugin:          rpm.Name,
						Justification:   vex.ComponentNotPresent,
						MatchesAllVulns: true,
					}},
				},
				{
					Name:     "not-in-db",
					Location: extractor.LocationFromPath("path/not/in/db"),
				},
			},
		},
		{
			desc: "ctx_cancelled",
			ctx:  cancelledContext,
			fakeFS: `
-- var/lib/rpm/Packages --
-> testdata/Packages
`,
			packages: []*extractor.Package{
				{
					Name:     "pyxattr",
					Location: extractor.LocationFromPath("usr/lib64/python2.7/site-packages/pyxattr-0.5.1-py2.7.egg-info"),
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "pyxattr",
					Location: extractor.LocationFromPath("usr/lib64/python2.7/site-packages/pyxattr-0.5.1-py2.7.egg-info"),
					// No annotations
				},
			},
			wantErr: cmpopts.AnyError,
		},
	}

	for _, fsType := range []string{"virtual_fs", "real_fs"} {
		for _, tt := range tests {
			t.Run(tt.desc+"_"+fsType, func(t *testing.T) {
				if tt.ctx == nil {
					tt.ctx = t.Context()
				}

				mfs, err := fakefs.PrepareFS(tt.fakeFS, fakefs.SimLinkModifier)
				if err != nil {
					t.Fatal(err)
				}
				input := &annotator.ScanInput{
					ScanRoot: &scalibrfs.ScanRoot{FS: mfs},
				}

				if fsType == "virtual_fs" {
					// Simulate a virtual FS by hiding the root path.
					input.ScanRoot.Path = ""
				}

				// Deep copy the packages to avoid modifying the original inventory that is used in other tests.
				packages := copier.Copy(tt.packages).([]*extractor.Package)
				inv := &inventory.Inventory{Packages: packages}

				anno, err := rpm.New(&cpb.PluginConfig{})
				if err != nil {
					t.Fatal(err)
				}

				err = anno.Annotate(tt.ctx, input, inv)
				if !cmp.Equal(tt.wantErr, err, cmpopts.EquateErrors()) {
					t.Fatalf("Annotate(%v) error: %v, want %v", tt.packages, err, tt.wantErr)
				}

				want := &inventory.Inventory{Packages: tt.wantPackages}
				if diff := cmp.Diff(want, inv); diff != "" {
					t.Errorf("Annotate(%v): unexpected diff (-want +got): %v", tt.packages, diff)
				}
			})
		}
	}
}
