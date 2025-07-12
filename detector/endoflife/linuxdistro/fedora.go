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

package linuxdistro

import (
	"strconv"
	"time"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

func checkSupportEnd(eos string) bool {
	date, err := time.Parse("2006-01-02", eos)
	if err != nil {
		return false
	}
	return date.Before(now())
}

func fedoraEOL(osRelease map[string]string, _ scalibrfs.FS) bool {
	if eos, ok := osRelease["SUPPORT_END"]; ok && checkSupportEnd(eos) {
		return true
	}
	if id, ok := osRelease["VERSION_ID"]; ok {
		i, err := strconv.Atoi(id)
		if err != nil {
			return false
		}
		// See: https://docs.fedoraproject.org/en-US/releases/eol/
		// Fedora 40 is currently the latest EoL release
		return i <= 40
	}
	return false
}
