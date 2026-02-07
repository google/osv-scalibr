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

// Package scanrunner provides the main function for running a scan with the SCALIBR binary.
package scanrunner

import (
	"context"

	scalibr "github.com/google/osv-scalibr"
	scalibrlayerimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/google/osv-scalibr/binary/cli"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/version"
)

// RunScan executes the scan with the given CLI flags
// and returns the exit code passed to os.Exit() in the main binary.
func RunScan(flags *cli.Flags) int {
	if flags.PrintVersion {
		log.Infof("OSV-SCALIBR v%s", version.ScannerVersion)
		return 0
	}

	if flags.Verbose {
		log.SetLogger(&log.DefaultLogger{Verbose: true})
	}

	cfg, err := flags.GetScanConfig()
	if err != nil {
		log.Errorf("%v.GetScanConfig(): %v", flags, err)
		return 1
	}

	log.Infof("Running scan with %d plugins", len(cfg.Plugins))
	if len(cfg.PathsToExtract) > 0 {
		log.Infof("Paths to extract: %s", cfg.PathsToExtract)
	}

	var result *scalibr.ScanResult
	if flags.ImageTarball != "" {
		layerCfg := scalibrlayerimage.DefaultConfig()
		log.Infof("Scanning image tarball: %s", flags.ImageTarball)
		img, err := scalibrlayerimage.FromTarball(flags.ImageTarball, layerCfg)
		if err != nil {
			log.Errorf("Failed to create image from tarball: %v", err)
			return 1
		}
		defer func() {
			if tmpErr := img.CleanUp(); tmpErr != nil {
				log.Errorf("Failed to clean up image: %v", tmpErr)
			}
		}()
		result, err = scalibr.New().ScanContainer(context.Background(), img, cfg)

		cleanupErr := img.CleanUp()
		if cleanupErr != nil {
			log.Errorf("failed to clean up image: %s", err)
		}

		if err != nil {
			log.Errorf("Failed to scan tarball: %v", err)
			return 1
		}
	} else if flags.ImageLocal != "" { // We will scan an image in the local hard disk
		layerCfg := scalibrlayerimage.DefaultConfig()
		log.Infof("Scanning local image: %s", flags.ImageLocal)
		img, err := scalibrlayerimage.FromLocalDockerImage(flags.ImageLocal, layerCfg)
		if err != nil {
			log.Errorf("Failed to scan local image: %v", err)
			return 1
		}
		defer func() {
			if tmpErr := img.CleanUp(); tmpErr != nil {
				log.Errorf("Failed to clean up image: %v", tmpErr)
			}
		}()
		result, err = scalibr.New().ScanContainer(context.Background(), img, cfg)
		if err != nil {
			log.Errorf("Failed to scan container: %v", err)
			return 1
		}
	} else {
		log.Infof("Scan roots: %s", cfg.ScanRoots)
		result = scalibr.New().Scan(context.Background(), cfg)
	}

	log.Infof("Scan status: %v", result.Status)
	for _, p := range result.PluginStatus {
		if p.Status.Status != plugin.ScanStatusSucceeded {
			log.Warnf("Plugin '%s' did not succeed. Status: %v, Reason: %s", p.Name, p.Status, p.Status.FailureReason)
		}
	}
	log.Infof(
		"Found %d software packages, %d security findings",
		len(result.Inventory.Packages),
		len(result.Inventory.PackageVulns)+len(result.Inventory.GenericFindings),
	)

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
