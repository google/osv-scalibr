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

package condaenv

import "testing"

func TestParseCondaSpec(t *testing.T) {
	tests := []struct {
		name        string
		spec        string
		wantName    string
		wantVersion string
	}{
		{
			name:        "single_equals_pin",
			spec:        "scipy=1.9.0",
			wantName:    "scipy",
			wantVersion: "1.9.0",
		},
		{
			name:        "double_equals_pin",
			spec:        "scipy==1.9.0",
			wantName:    "scipy",
			wantVersion: "1.9.0",
		},
		{
			name:        "pin_with_build_string",
			spec:        "numpy=1.23.0=py310h5f1b942_0",
			wantName:    "numpy",
			wantVersion: "1.23.0",
		},
		{
			name:        "channel_prefix_is_dropped",
			spec:        "conda-forge::pandas=1.5.3",
			wantName:    "pandas",
			wantVersion: "1.5.3",
		},
		{
			name:        "space_separated_match_spec",
			spec:        "cryptography 38.0.0 py310h597c629_0",
			wantName:    "cryptography",
			wantVersion: "38.0.0",
		},
		{
			name:        "space_separated_without_build_string",
			spec:        "numpy 1.26.0",
			wantName:    "numpy",
			wantVersion: "1.26.0",
		},
		{
			name:        "surrounding_whitespace_is_trimmed",
			spec:        "  scipy=1.9.0  ",
			wantName:    "scipy",
			wantVersion: "1.9.0",
		},
		{
			name:        "epoch_and_local_version",
			spec:        "openssl=1!1.1.1w+local",
			wantName:    "openssl",
			wantVersion: "1!1.1.1w+local",
		},
		{
			name:        "patch_wildcard_reports_the_series",
			spec:        "numpy=1.26.*",
			wantName:    "numpy",
			wantVersion: "1.26",
		},
		{
			name:        "minor_wildcard_reports_the_series",
			spec:        "scipy=1.*",
			wantName:    "scipy",
			wantVersion: "1",
		},
		{
			name: "bare_wildcard_is_not_a_version",
			spec: "pandas=*",
		},
		{
			name: "no_version_constraint",
			spec: "numpy",
		},
		{
			name: "empty_spec",
			spec: "   ",
		},
		{
			name: "lower_bound_range",
			spec: "scipy>=1.9.0",
		},
		{
			name: "upper_bound_range",
			spec: "pandas<=1.5.3",
		},
		{
			name: "exclusion",
			spec: "matplotlib!=3.6.0",
		},
		{
			name: "compatible_release",
			spec: "torch~=2.0",
		},
		{
			name: "greater_than",
			spec: "jax>1.0",
		},
		{
			name: "compound_constraint",
			spec: "numpy>=1.23,<2.0",
		},
		{
			name: "space_separated_range",
			spec: "scipy >=1.9.0",
		},
		{
			name: "version_without_a_leading_digit",
			spec: "numpy=latest",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotName, gotVersion := parseCondaSpec(tc.spec)
			if gotName != tc.wantName || gotVersion != tc.wantVersion {
				t.Errorf("parseCondaSpec(%q) = (%q, %q), want (%q, %q)",
					tc.spec, gotName, gotVersion, tc.wantName, tc.wantVersion)
			}
		})
	}
}

func TestParsePipRequirement(t *testing.T) {
	tests := []struct {
		name        string
		req         string
		wantName    string
		wantVersion string
	}{
		{
			name:        "exact_pin",
			req:         "tensorflow==2.10.0",
			wantName:    "tensorflow",
			wantVersion: "2.10.0",
		},
		{
			name:        "arbitrary_equality",
			req:         "requests===2.28.1",
			wantName:    "requests",
			wantVersion: "2.28.1",
		},
		{
			name:        "extras_are_dropped",
			req:         "celery[redis]==5.2.7",
			wantName:    "celery",
			wantVersion: "5.2.7",
		},
		{
			name:        "environment_marker_is_dropped",
			req:         `torch==1.13.0; python_version<"3.11"`,
			wantName:    "torch",
			wantVersion: "1.13.0",
		},
		{
			name:        "whitespace_around_the_operator",
			req:         "torch == 1.13.0",
			wantName:    "torch",
			wantVersion: "1.13.0",
		},
		{
			name:        "wildcard_reports_the_series",
			req:         "torch==2.0.*",
			wantName:    "torch",
			wantVersion: "2.0",
		},
		{
			name: "lower_bound_range",
			req:  "tensorflow>=2.10",
		},
		{
			name: "compound_specifier",
			req:  "scikit-learn==1.2.0,!=1.2.1",
		},
		{
			name: "no_version",
			req:  "tensorflow",
		},
		{
			name: "requirements_file_option",
			req:  "-r extra-requirements.txt",
		},
		{
			name: "editable_install_option",
			req:  "-e .",
		},
		{
			name: "index_url_option",
			req:  "--index-url https://pypi.org/simple",
		},
		{
			name: "direct_reference",
			req:  "torch @ https://download.pytorch.org/whl/torch-2.0.0.whl",
		},
		{
			name: "vcs_reference",
			req:  "git+https://github.com/huggingface/transformers.git",
		},
		{
			name: "local_path",
			req:  "../lib",
		},
		{
			name: "empty_requirement",
			req:  "  ",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotName, gotVersion := parsePipRequirement(tc.req)
			if gotName != tc.wantName || gotVersion != tc.wantVersion {
				t.Errorf("parsePipRequirement(%q) = (%q, %q), want (%q, %q)",
					tc.req, gotName, gotVersion, tc.wantName, tc.wantVersion)
			}
		})
	}
}
