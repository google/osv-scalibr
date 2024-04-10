// Copyright 2024 Google LLC
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

package internal

import "path/filepath"

// BuildTransitiveMaps fills the transitive map with aggregated numbers from subdirs.
func BuildTransitiveMaps(m map[string]int) map[string]int {
	transitive := map[string]int{}
	for p, inodes := range m {
		d := p
		for d != "." && d != "/" && d != "c:\\" && d != "c:/" {
			d = filepath.Dir(d)
			transitive[d] += inodes
		}
	}
	return transitive
}
