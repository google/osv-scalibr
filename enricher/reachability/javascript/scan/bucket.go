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

package scan

import (
	"errors"
	"time"

	"github.com/google/osv-scalibr/enricher/reachability/javascript/internal"
)

// ErrBucketTimeout is returned by RunOneBucket when the underlying jelly
// invocation reported a timeout (either subprocess wall-clock or jelly's
// internal timer). RunPhase2 splits the bucket on this error.
var ErrBucketTimeout = errors.New("jelly bucket timed out")

// ErrBucketTerminatedEarly is returned by RunOneBucket when jelly produced
// some output but flagged the run as untrustworthy (Aborted, LowMemory,
// RangeError, or non-zero subprocess exit). RunPhase2 advances the
// heuristic on this — splitting wouldn't help if the analyzer itself is
// failing.
var ErrBucketTerminatedEarly = errors.New("jelly bucket terminated early")

// Bucket is one unit of work for Phase 2 — a set of vulns to analyze
// together under a given heuristic + timeout.
type Bucket struct {
	Heuristic  Heuristic
	Vulns      []*internal.VulnRef
	Timeout    time.Duration
	SplitDepth int // for telemetry; increments each recursive split
}

// Split returns two sub-buckets covering the input vulns, each with the
// given timeout. Partitions roughly in half.
func (b Bucket) Split(newTimeout time.Duration) (Bucket, Bucket) {
	mid := len(b.Vulns) / 2
	left := Bucket{
		Heuristic:  b.Heuristic,
		Vulns:      b.Vulns[:mid],
		Timeout:    newTimeout,
		SplitDepth: b.SplitDepth + 1,
	}
	right := Bucket{
		Heuristic:  b.Heuristic,
		Vulns:      b.Vulns[mid:],
		Timeout:    newTimeout,
		SplitDepth: b.SplitDepth + 1,
	}
	return left, right
}
