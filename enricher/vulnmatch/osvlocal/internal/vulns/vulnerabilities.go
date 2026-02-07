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

// Package vulns provides utility functions for working with vulnerabilities.
package vulns

import osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"

// Include checks if the slice of vulnerabilities includes the given vulnerability
func Include(vs []*osvpb.Vulnerability, vulnerability *osvpb.Vulnerability) bool {
	for _, vuln := range vs {
		if vuln.GetId() == vulnerability.GetId() {
			return true
		}
	}

	return false
}
