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

//go:build windows

package jelly

import (
	"context"
	"errors"
	"time"
)

// Available always reports false on Windows so the enricher cleanly
// skips. The Unix implementation requires process groups (Setpgid +
// Kill(-pid)) for race-free timeout handling, neither of which has a
// direct Windows equivalent we want to maintain.
func (c *realClient) Available(_ context.Context) bool { return false }

// errJellyUnsupportedOnWindows is what runJelly returns on Windows. The
// rest of the enricher treats jelly toolchain unavailability as a clean
// skip (Enricher.Available returns false → Enrich returns nil with no
// signals), so this error surfaces only if a Windows caller bypasses the
// Available gate.
var errJellyUnsupportedOnWindows = errors.New("jelly subprocess is not supported on Windows (requires unix process groups)")

// runJelly is a stub on Windows. The Unix implementation uses
// syscall.SysProcAttr.Setpgid + syscall.Kill(-pid) for process-group
// signaling, neither of which exists on Windows; rather than ship a
// half-implementation we refuse cleanly. Available() already returns
// false on Windows so this path is normally unreachable.
func (c *realClient) runJelly(_ context.Context, _ []string, _ time.Duration) (terminationCause, error) {
	// Reference fields that only the Unix runJelly reads, so the
	// Windows build's "unused" linter doesn't fire on the shared
	// realClient struct.
	_ = c.nodeOptions
	return terminationNormal, errJellyUnsupportedOnWindows
}
