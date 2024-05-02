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

// Package scanrunner provides the main function for running a scan with the SCALIBR binary.
package scanrunner

import (
	"context"

	"github.com/google/osv-scalibr/binary/cli"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	scalibr "github.com/google/osv-scalibr"
)

// RunScan executes the scan with the given CLI flags
// and returns the exit code passed to os.Exit() in the main binary.
func RunScan(flags *cli.Flags) int {
	if flags.Verbose {
		log.SetLogger(&log.DefaultLogger{Verbose: true})
	}

	cfg, err := flags.GetScanConfig()
	if err != nil {
		log.Errorf("%v.GetScanConfig(): %v", flags, err)
		return 1
	}

	log.Infof("Running scan with %d extractors and %d detectors", len(cfg.InventoryExtractors), len(cfg.Detectors))
	log.Infof("Scan root: %s", cfg.ScanRoot)
	if len(cfg.FilesToExtract) > 0 {
		log.Infof("Files to extract: %s", cfg.FilesToExtract)
	}
	result := scalibr.New().Scan(context.Background(), cfg)

	log.Infof("Scan status: %v", result.Status)
	log.Infof("Found %d software inventories, %d security findings", len(result.Inventories), len(result.Findings))

	if err := flags.WriteScanResults(result); err != nil {
		log.Errorf("Error writing scan results: %v", err)
		return 1
	}

	if result.Status.Status != plugin.ScanStatusSucceeded {
		log.Errorf("Scan wasn't successful: %s", result.Status.FailureReason)
		return 1
	}

	return 0
}
