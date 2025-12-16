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

package binary

import (
	"encoding/json"

	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

// govulncheckMessage contains the relevant parts of the json output of govulncheck.
type govulncheckMessage struct {
	OSV     *osvpb.Vulnerability `json:"osv,omitempty"`
	Finding *govulncheckFinding  `json:"finding,omitempty"`
}

// UnmarshalJSON unmarshals the govulncheck message. The OSV field is a proto
// message, so it needs to be unmarshaled with protojson.
func (m *govulncheckMessage) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if osv, ok := raw["osv"]; ok {
		m.OSV = &osvpb.Vulnerability{}
		if err := protojson.Unmarshal(osv, m.OSV); err != nil {
			return err
		}
	}
	if finding, ok := raw["finding"]; ok {
		if err := json.Unmarshal(finding, &m.Finding); err != nil {
			return err
		}
	}
	return nil
}

// govulncheckFinding is a trimmed down version of govulncheck finding.
type govulncheckFinding struct {
	OSV   string              `json:"osv,omitempty"`
	Trace []*govulncheckFrame `json:"trace,omitempty"`
}

type govulncheckFrame struct {
	// Function is the detected symbol.
	Function string `json:"function,omitempty"`
}
