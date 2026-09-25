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
	"os"
	"os/exec"
	"syscall"
	"time"
)

const minNodeMajor = 22

// Available checks that jelly and node >= 22 are installed.
func (c *realClient) Available(ctx context.Context) bool {
	if !c.jellyBinaryAvailable(ctx) {
		return false
	}
	out, err := exec.CommandContext(ctx, "node", "--version").Output()
	if err != nil {
		return false
	}
	major, ok := parseNodeMajor(string(out))
	return ok && major >= minNodeMajor
}

func (c *realClient) jellyBinaryAvailable(_ context.Context) bool {
	if c.jellyLookupPath != "" {
		_, err := exec.LookPath(c.jellyLookupPath)
		return err == nil
	}
	_, err := exec.LookPath("jelly")
	return err == nil
}

// timeoutMultiplier wraps args.Timeout with 1.5× wall-clock to guard against
// jelly's internal timer drifting under GC pressure on large inputs.
const timeoutMultiplier = 3.0 / 2.0

// runJelly spawns the jelly binary with the given flags, enforcing a
// wall-clock timeout of 1.5× internalTimeout (SIGKILL on the process
// group). Returns (cause, err).
//
// Kill-vs-reap race is avoided by serializing through a non-blocking
// re-check of waitCh once runCtx fires: if Wait already returned, we
// don't kill at all (the leader is reaped and the PID may be recycled).
// Otherwise we SIGKILL the group, then drain waitCh.
//
// Cause classification is the SOLE signal for what kind of termination
// happened — the returned error is the raw waitErr/ctx.Err(), NEVER
// wrapped with a context sentinel that would let an inner wall-clock
// timeout be confused for a parent-deadline cancellation. Callers
// switch on cause, not errors.Is.
func (c *realClient) runJelly(ctx context.Context, flags []string, internalTimeout time.Duration) (terminationCause, error) {
	wall := time.Duration(float64(internalTimeout) * timeoutMultiplier)
	runCtx, cancel := context.WithTimeout(ctx, wall)
	defer cancel()

	cmd := exec.CommandContext(runCtx, "jelly", flags...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // so we can signal the group
	cmd.Env = withNodeOptions(os.Environ(), c.nodeOptions)
	if err := cmd.Start(); err != nil {
		return terminationNormal, err
	}
	pid := cmd.Process.Pid

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	select {
	case <-runCtx.Done():
		// runCtx fired. The process may have exited on its own at the
		// same instant. Re-check waitCh non-blocking first: if ready
		// AND the wait succeeded, the process beat the deadline and we
		// don't classify as a timeout.
		select {
		case err := <-waitCh:
			if err == nil {
				return terminationNormal, nil
			}
			return classify(ctx, runCtx, err)
		default:
			_ = syscall.Kill(-pid, syscall.SIGKILL)
			err := <-waitCh
			return classify(ctx, runCtx, err)
		}
	case err := <-waitCh:
		return terminationNormal, err
	}
}

// classify maps (parent ctx, runCtx, wait err) → (cause, error). Parent
// cancellation (Canceled or DeadlineExceeded) returns the parent's err
// verbatim — it already satisfies errors.Is(Canceled/DeadlineExceeded)
// for downstream propagation. Our own wall-clock timeout returns the
// raw waitErr WITHOUT wrapping; the cause enum is the signal.
func classify(parent, run context.Context, waitErr error) (terminationCause, error) {
	if parent.Err() != nil {
		return terminationCanceled, parent.Err()
	}
	if errors.Is(run.Err(), context.DeadlineExceeded) {
		// Our own wall-clock guard fired. Return waitErr unwrapped so
		// callers can distinguish via cause: terminationTimedOut means
		// LOCAL guard, terminationCanceled means parent issue.
		return terminationTimedOut, waitErr
	}
	// Shouldn't happen — runCtx.Done fired but neither parent nor our
	// own deadline tripped. Return a non-nil error so the caller's
	// "cancellation = nil error path" assumption can't silently produce
	// an empty result set.
	if waitErr == nil {
		waitErr = errors.New("jelly: subprocess terminated for unknown reason")
	}
	return terminationCanceled, waitErr
}
