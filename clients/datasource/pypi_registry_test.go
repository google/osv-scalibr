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

package datasource_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/clients/clienttest"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/clients/datasource/internal/pypi"
)

func TestGetPackageInfo(t *testing.T) {
	srv := clienttest.NewMockHTTPServer(t)
	client := datasource.NewPyPIRegistryAPIClient(srv.URL)
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

	got, err := client.GetPackageInfo(context.Background(), "abc")
	if err != nil {
		t.Fatalf("failed to get PyPI package info %s: %v", "abc", err)
	}
	want := pypi.Response{
		Releases: pypi.Releases{
			"1.0.0": []pypi.Release{
				{Digests: pypi.Digests{SHA256: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"}},
			},
			"2.0.0": []pypi.Release{
				{Digests: pypi.Digests{SHA256: "7259c75c05335b71328905296c425026859546059b02a6144e59049755452292"}},
				{Digests: pypi.Digests{SHA256: "47250e501570778c18251e06497f5664a7538d61895a97576f30a47d21c430e7"}},
			},
			"3.0.0": []pypi.Release{
				{Digests: pypi.Digests{SHA256: "93f53801a2434547b74457e7c53d3663a898492f25492af7e721a9557b4b10b0"}},
			},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("GetPackageInfo(%s) mismatch (-want +got):\n%s", "abc", diff)
	}
}

func TestGetVersionInfo(t *testing.T) {
	srv := clienttest.NewMockHTTPServer(t)
	client := datasource.NewPyPIRegistryAPIClient(srv.URL)
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

	got, err := client.GetVersionInfo(context.Background(), "abc", "1.0.0")
	if err != nil {
		t.Fatalf("failed to get PyPI version info %s %s: %v", "abc", "1.0.0", err)
	}
	want := pypi.Response{
		Info: pypi.Info{
			RequiresDist: []string{
				"charset-normalizer (<4,>=2)",
				"idna (<4,>=2.5)",
				"urllib3 (<3,>=1.21.1)",
				"certifi (>=2017.4.17)",
				"PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'",
				"chardet (<6,>=3.0.2) ; extra == 'use_chardet_on_py3'",
			},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("GetVersionInfo(%s, %s) mismatch (-want +got):\n%s", "abc", "1.0.0", diff)
	}
}
