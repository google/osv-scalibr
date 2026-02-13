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

package vulns_test

import (
	"testing"

	"github.com/google/osv-scalibr/enricher/vulnmatch/osvlocal/internal/vulns"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestVulnerabilities_Includes(t *testing.T) {
	type args struct {
		osv *osvpb.Vulnerability
	}
	tests := []struct {
		name string
		vs   []*osvpb.Vulnerability
		args args
		want bool
	}{
		{
			name: "",
			vs: []*osvpb.Vulnerability{
				{
					Id:      "GHSA-1",
					Aliases: []string{},
				},
			},
			args: args{
				osv: &osvpb.Vulnerability{
					Id:      "GHSA-2",
					Aliases: []string{},
				},
			},
			want: false,
		},
		{
			name: "",
			vs: []*osvpb.Vulnerability{
				{
					Id:      "GHSA-1",
					Aliases: []string{},
				},
			},
			args: args{
				osv: &osvpb.Vulnerability{
					Id:      "GHSA-1",
					Aliases: []string{},
				},
			},
			want: true,
		},
		{
			name: "",
			vs: []*osvpb.Vulnerability{
				{
					Id:      "GHSA-1",
					Aliases: []string{"GHSA-2"},
				},
			},
			args: args{
				osv: &osvpb.Vulnerability{
					Id:      "GHSA-2",
					Aliases: []string{},
				},
			},
			want: false,
		},
		{
			name: "",
			vs: []*osvpb.Vulnerability{
				{
					Id:      "GHSA-1",
					Aliases: []string{},
				},
			},
			args: args{
				osv: &osvpb.Vulnerability{
					Id:      "GHSA-2",
					Aliases: []string{"GHSA-1"},
				},
			},
			want: false,
		},
		{
			name: "",
			vs: []*osvpb.Vulnerability{
				{
					Id:      "GHSA-1",
					Aliases: []string{"CVE-1"},
				},
			},
			args: args{
				osv: &osvpb.Vulnerability{
					Id:      "GHSA-2",
					Aliases: []string{"CVE-1"},
				},
			},
			want: false,
		},
		{
			name: "",
			vs: []*osvpb.Vulnerability{
				{
					Id:      "GHSA-1",
					Aliases: []string{"CVE-2"},
				},
			},
			args: args{
				osv: &osvpb.Vulnerability{
					Id:      "GHSA-2",
					Aliases: []string{"CVE-2"},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := vulns.Include(tt.vs, tt.args.osv); got != tt.want {
				t.Errorf("Includes() = %v, want %v", got, tt.want)
			}
		})
	}
}
