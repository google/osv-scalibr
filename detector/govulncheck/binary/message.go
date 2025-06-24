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

import "github.com/ossf/osv-schema/bindings/go/osvschema"

// govulncheckMessage contains the relevant parts of the json output of govulncheck.
type govulncheckMessage struct {
	OSV     *osvschema.Vulnerability `json:"osv,omitempty"`
	Finding *govulncheckFinding      `json:"finding,omitempty"`
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
