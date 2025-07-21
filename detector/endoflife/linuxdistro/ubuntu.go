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
	"bufio"
	"time"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

type ubuntuReleaseSupport struct {
	standard time.Time
	pro      time.Time
	legacy   time.Time
}

func rdate(year int, month time.Month) time.Time {
	return time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
}

// From https://ubuntu.com/about/release-cycle
var ubuntuReleases = map[string]ubuntuReleaseSupport{
	"25.04": {
		standard: rdate(2026, time.January),
		pro:      time.Time{},
		legacy:   time.Time{},
	},
	"24.10": {
		standard: rdate(2025, time.July),
		pro:      time.Time{},
		legacy:   time.Time{},
	},
	"24.04": {
		standard: rdate(2029, time.April),
		pro:      rdate(2034, time.April),
		legacy:   rdate(2036, time.April),
	},
	"22.04": {
		standard: rdate(2027, time.April),
		pro:      rdate(2032, time.April),
		legacy:   rdate(2034, time.April),
	},
	"20.04": {
		standard: rdate(2025, time.May),
		pro:      rdate(2030, time.April),
		legacy:   rdate(2032, time.April),
	},
	"18.04": {
		standard: rdate(2023, time.May),
		pro:      rdate(2028, time.April),
		legacy:   rdate(2030, time.April),
	},
	"16.04": {
		standard: rdate(2021, time.April),
		pro:      rdate(2026, time.April),
		legacy:   rdate(2028, time.April),
	},
	"14.04": {
		standard: rdate(2019, time.April),
		pro:      rdate(2024, time.April),
		legacy:   rdate(2026, time.April),
	},
}

// See https://ubuntu.com/about/release-cycle
func ubuntuEOL(osRelease map[string]string, fs scalibrfs.FS) bool {
	id, ok := osRelease["VERSION_ID"]
	if !ok {
		return false
	}
	if release, ok := ubuntuReleases[id]; ok {
		if isUbuntuLegacy(fs) {
			return release.legacy.Before(now())
		}
		if isUbuntuPro(fs) {
			return release.pro.Before(now())
		}
		return release.standard.Before(now())
	}
	return false
}

func isUbuntuPro(fs scalibrfs.FS) bool {
	// We could also check '/var/lib/ubuntu-advantage/status.json'
	f, err := fs.Open("/etc/apt/sources.list.d/ubuntu-esm-infra.sources")
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		return scanner.Text() == "# Written by ubuntu-pro-client"
	}
	return false
}

func isUbuntuLegacy(fs scalibrfs.FS) bool {
	// TODO(#889): Implement.
	return false
}
