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

//go:build unix

package jelly

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestClassify_ParentCanceled(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	run, runCancel := context.WithCancel(parent)
	defer runCancel()
	gotCause, gotErr := classify(parent, run, nil)
	if gotCause != terminationCanceled {
		t.Errorf("cause = %v, want terminationCanceled", gotCause)
	}
	if !errors.Is(gotErr, context.Canceled) {
		t.Errorf("err = %v, want errors.Is(context.Canceled)", gotErr)
	}
}

func TestClassify_ParentDeadlineExceeded(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	parent, cancel := context.WithDeadline(context.Background(), past)
	defer cancel()
	<-parent.Done() // ensure parent.Err() is non-nil
	run, runCancel := context.WithCancel(parent)
	defer runCancel()
	gotCause, gotErr := classify(parent, run, errors.New("signal: killed"))
	if gotCause != terminationCanceled {
		t.Errorf("cause = %v, want terminationCanceled (parent deadline counts as cancellation upstream)", gotCause)
	}
	if !errors.Is(gotErr, context.DeadlineExceeded) {
		t.Errorf("err = %v, want errors.Is(context.DeadlineExceeded) (parent deadline propagated verbatim)", gotErr)
	}
}

func TestClassify_LocalDeadlineExceeded(t *testing.T) {
	parent := context.Background()
	past := time.Now().Add(-time.Hour)
	run, cancel := context.WithDeadline(context.Background(), past)
	defer cancel()
	<-run.Done()
	waitErr := errors.New("signal: killed")
	gotCause, gotErr := classify(parent, run, waitErr)
	if gotCause != terminationTimedOut {
		t.Errorf("cause = %v, want terminationTimedOut", gotCause)
	}
	// Local timeout returns waitErr unwrapped so callers can distinguish
	// via cause; errors.Is(context.DeadlineExceeded) is intentionally
	// false here (parent ctx never expired).
	if errors.Is(gotErr, context.DeadlineExceeded) {
		t.Errorf("local-timeout waitErr must NOT satisfy errors.Is(DeadlineExceeded); got %v", gotErr)
	}
	if !errors.Is(gotErr, waitErr) {
		t.Errorf("err = %v, want the raw waitErr passed in", gotErr)
	}
}

func TestClassify_DefensiveShouldntHappenBranchReturnsNonNilErr(t *testing.T) {
	// Synthetic case: runCtx.Done has fired but neither parent.Err() nor
	// run.Err() is non-nil. Cannot be reached via stdlib context today,
	// but the defensive branch must guarantee a non-nil error so the
	// caller's "cause==terminationCanceled => non-nil err" invariant
	// holds (a nil err would let the caller return ScanResult{}, nil and
	// silently mark every vuln as Skipped/no-data).
	parent := context.Background()
	run := context.Background()
	gotCause, gotErr := classify(parent, run, nil)
	if gotCause != terminationCanceled {
		t.Errorf("cause = %v, want terminationCanceled", gotCause)
	}
	if gotErr == nil {
		t.Error("defensive branch must return non-nil err so cancellation can't slip through as silent success")
	}
}
