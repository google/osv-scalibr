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

package resolution_test

import (
	"context"
	"testing"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/clients/clienttest"
	"github.com/google/osv-scalibr/clients/resolution"
)

func TestVersions(t *testing.T) {
	srv := clienttest.NewMockHTTPServer(t)
	srv.SetResponse(t, "abc/json", []byte(`
	{
		"releases": {
			"1.0.0": [
				{
					"digests": {
						"sha256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
					}
				}
			],
			"2.0.0": [
				{
					"digests": {
						"sha256": "7259c75c05335b71328905296c425026859546059b02a6144e59049755452292"
					}
				},
				{
					"digests": {
						"sha256": "47250e501570778c18251e06497f5664a7538d61895a97576f30a47d21c430e7"
					}
				}
			],
			"3.0.0": [
				{
					"digests": {
						"sha256": "93f53801a2434547b74457e7c53d3663a898492f25492af7e721a9557b4b10b0"
					}
				}
			]
		}
	}
	`))

	pk := resolve.PackageKey{
		System: resolve.PyPI,
		Name:   "abc",
	}
	client := resolution.NewPyPIRegistryClient(srv.URL)
	got, err := client.Versions(context.Background(), pk)
	if err != nil {
		t.Fatalf("failed to get versions %v: %v", pk, err)
	}
	want := []resolve.Version{
		resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey:  pk,
				Version:     "1.0.0",
				VersionType: resolve.Concrete,
			},
		},
		resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey:  pk,
				Version:     "2.0.0",
				VersionType: resolve.Concrete,
			},
		},
		resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey:  pk,
				Version:     "3.0.0",
				VersionType: resolve.Concrete,
			},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Versions(%v) mismatch (-want +got):\n%s", pk, diff)
	}
}

func TestRequirements(t *testing.T) {
	srv := clienttest.NewMockHTTPServer(t)
	srv.SetResponse(t, "abc/1.0.0/json", []byte(`
	{
		"info": {
			"requires_dist": [
				"charset-normalizer (<4,>=2)",
				"idna (<4,>=2.5)",
				"urllib3 (<3,>=1.21.1)",
				"certifi (>=2017.4.17)",
				"PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'",
				"chardet (<6,>=3.0.2) ; extra == 'use_chardet_on_py3'"
			]
		}
	}
	`))

	vk := resolve.VersionKey{
		PackageKey: resolve.PackageKey{
			System: resolve.PyPI,
			Name:   "abc",
		},
		Version:     "1.0.0",
		VersionType: resolve.Concrete,
	}
	client := resolution.NewPyPIRegistryClient(srv.URL)
	got, err := client.Requirements(context.Background(), vk)
	if err != nil {
		t.Fatalf("failed to get requirements %v: %v", vk, err)
	}

	t1 := dep.NewType()
	t1.AddAttr(dep.Environment, "extra == 'socks'")
	t2 := dep.NewType()
	t2.AddAttr(dep.Environment, "extra == 'use_chardet_on_py3'")
	want := []resolve.RequirementVersion{
		resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.PyPI,
					Name:   "charset-normalizer",
				},
				Version:     "<4,>=2",
				VersionType: resolve.Requirement,
			},
		},
		resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.PyPI,
					Name:   "idna",
				},
				Version:     "<4,>=2.5",
				VersionType: resolve.Requirement,
			},
		},
		resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.PyPI,
					Name:   "urllib3",
				},
				Version:     "<3,>=1.21.1",
				VersionType: resolve.Requirement,
			},
		},
		resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.PyPI,
					Name:   "certifi",
				},
				Version:     ">=2017.4.17",
				VersionType: resolve.Requirement,
			},
		},
		resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.PyPI,
					Name:   "pysocks",
				},
				Version:     "!=1.5.7,>=1.5.6",
				VersionType: resolve.Requirement,
			},
			Type: t1,
		},
		resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.PyPI,
					Name:   "chardet",
				},
				Version:     "<6,>=3.0.2",
				VersionType: resolve.Requirement,
			},
			Type: t2,
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Requirements(%v) mismatch (-want +got):\n%s", vk, diff)
	}
}
