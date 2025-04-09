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

package extracttest

import (
	"cmp"
	"fmt"

	"github.com/google/osv-scalibr/extractor"
)

// PackageCmpLess is a comparator function for Packages, to be used in
// tests with cmp.Diff to disregard the order in which the Packages
// are reported.
func PackageCmpLess(a, b *extractor.Package) bool {
	aLoc := fmt.Sprintf("%v", a.Locations)
	bLoc := fmt.Sprintf("%v", b.Locations)

	var aExtr, bExtr string
	if a.Extractor != nil {
		aExtr = a.Extractor.Name()
	}
	if b.Extractor != nil {
		bExtr = b.Extractor.Name()
	}

	aSourceCode := fmt.Sprintf("%v", a.SourceCode)
	bSourceCode := fmt.Sprintf("%v", b.SourceCode)

	return cmp.Or(
		cmp.Compare(aLoc, bLoc),
		cmp.Compare(a.Name, b.Name),
		cmp.Compare(a.Version, b.Version),
		cmp.Compare(aSourceCode, bSourceCode),
		cmp.Compare(aExtr, bExtr),
	) < 0
}
