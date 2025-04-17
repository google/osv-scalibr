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

// Package detectorrunner provides a Run function to help with running detectors
package detectorrunner

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/google/osv-scalibr/detector"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/stats"
)

// LINT.ThenChange(/binary/proto/scan_result.proto)

// Run runs the specified detectors and returns their findings,
// as well as info about whether the plugin runs completed successfully.
func Run(ctx context.Context, c stats.Collector, detectors []detector.Detector, scanRoot *scalibrfs.ScanRoot, index *packageindex.PackageIndex) ([]*detector.Finding, []*plugin.Status, error) {
	findings := []*detector.Finding{}
	status := []*plugin.Status{}
	for _, d := range detectors {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		start := time.Now()
		results, err := d.Scan(ctx, scanRoot, index)
		c.AfterDetectorRun(d.Name(), time.Since(start), err)
		for _, f := range results {
			f.Detectors = []string{d.Name()}
		}
		findings = append(findings, results...)
		status = append(status, plugin.StatusFromErr(d, false, err))
	}
	if err := validateAdvisories(findings); err != nil {
		return []*detector.Finding{}, status, err
	}
	return findings, status, nil
}

func validateAdvisories(findings []*detector.Finding) error {
	// Check that findings with the same advisory ID have identical advisories.
	ids := make(map[detector.AdvisoryID]detector.Advisory)
	for _, f := range findings {
		if f.Adv == nil {
			return fmt.Errorf("finding has no advisory set: %v", f)
		}
		if f.Adv.ID == nil {
			return fmt.Errorf("finding has no advisory ID set: %v", f)
		}
		if adv, ok := ids[*f.Adv.ID]; ok {
			if !reflect.DeepEqual(adv, *f.Adv) {
				return fmt.Errorf("multiple non-identical advisories with ID %v", f.Adv.ID)
			}
		}
		ids[*f.Adv.ID] = *f.Adv
	}
	return nil
}
