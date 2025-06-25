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

// Package result provides the ScanResult struct.
package result

import (
	"time"

	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// LINT.IfChange

// ScanResult stores the results of a scan incl. scan status and inventory found.
type ScanResult struct {
	Version   string
	StartTime time.Time
	EndTime   time.Time
	// Status of the overall scan.
	Status *plugin.ScanStatus
	// Status and versions of the plugins that ran.
	PluginStatus []*plugin.Status
	Inventory    inventory.Inventory
}

// LINT.ThenChange(/binary/proto/scan_result.proto)
