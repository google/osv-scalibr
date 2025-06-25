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

// Package winproducts contains information about Windows products.
package winproducts

import (
	"strings"

	"github.com/google/osv-scalibr/log"
)

var (
	// windowsFlavorAndBuildToProductName maps a given Windows flavor and build number to a product
	// name.
	windowsFlavorAndBuildToProductName = map[string]map[string]string{
		"server": {
			"6.0.6003":   "windows_server_2008",
			"6.1.7601":   "windows_server_2008:r2",
			"6.2.9200":   "windows_server_2012",
			"6.3.9600":   "windows_server_2012:r2",
			"10.0.14393": "windows_server_2016",
			"10.0.17763": "windows_server_2019",
			"10.0.20348": "windows_server_2022",
			"10.0.25398": "windows_server_2022:23H2",
			"10.0.26100": "windows_server_2025",
		},
		"client": {
			"5.1.2600":   "windows_xp",
			"10.0.10240": "windows_10:1507",
			"10.0.14393": "windows_10:1607",
			"10.0.17763": "windows_10:1809",
			"10.0.19042": "windows_10:20H2",
			"10.0.19043": "windows_10:21H1",
			"10.0.19044": "windows_10:21H2",
			"10.0.19045": "windows_10:22H2",
			"10.0.22000": "windows_11:21H2",
			"10.0.22621": "windows_11:22H2",
			"10.0.22631": "windows_11:23H2",
			"10.0.26100": "windows_11:24H2",
		},
	}
)

// windowsFlavor returns the lowercase Windows flavor (server or client) of the current system
// using the provided lowercase installType (found in the registry).
// Defaults to "server" if we don't recognize the flavor, but log so that we can add it later.
func windowsFlavor(installType string) string {
	flavor := strings.ToLower(installType)

	switch flavor {
	case "client":
		return "client"
	case "server", "server core":
		return "server"
	}

	log.Infof("Please report to scalibr devteam: unknown Windows flavor: %q", flavor)
	return "server"
}

// WindowsProductFromVersion fetches the current Windows product name from known products using
// the flavor (e.g. client / server) and the image version.
func WindowsProductFromVersion(flavor, imgVersion string) string {
	knownVersions, ok := windowsFlavorAndBuildToProductName[flavor]
	if !ok {
		return "unknownWindows"
	}

	imgVersionSplit := strings.Split(imgVersion, ".")
	if len(imgVersionSplit) < 3 {
		return "unknownWindows"
	}

	version := strings.Join(imgVersionSplit[:3], ".")
	if productName, ok := knownVersions[version]; ok {
		return productName
	}

	return "unknownWindows"
}
