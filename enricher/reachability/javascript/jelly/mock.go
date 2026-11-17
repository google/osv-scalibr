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

package jelly

import (
	"context"
)

// MockClient is a test double for the Client interface. It is intentionally
// exported (not in a _test.go file) so the scan/ sub-package's external test
// files can construct one. Production code MUST NOT instantiate MockClient —
// callers should always go through NewRealClient.
type MockClient struct {
	AvailableResult bool

	ImportResult ImportResult
	ImportErr    error
	ImportCalls  []ImportOnlyArgs

	FullScanResults []ScanResult // popped off the front per call
	FullScanErrs    []error
	FullScanCalls   []FullScanArgs
}

// Available returns the prebuilt result.
func (m *MockClient) Available(ctx context.Context) bool { return m.AvailableResult }

// RunImportOnly records args and returns the canned result.
func (m *MockClient) RunImportOnly(ctx context.Context, a ImportOnlyArgs) (ImportResult, error) {
	m.ImportCalls = append(m.ImportCalls, a)
	return m.ImportResult, m.ImportErr
}

// RunFullScan pops the next canned result/err off the slice.
func (m *MockClient) RunFullScan(ctx context.Context, a FullScanArgs) (ScanResult, error) {
	m.FullScanCalls = append(m.FullScanCalls, a)
	var res ScanResult
	var err error
	if len(m.FullScanResults) > 0 {
		res = m.FullScanResults[0]
		m.FullScanResults = m.FullScanResults[1:]
	}
	if len(m.FullScanErrs) > 0 {
		err = m.FullScanErrs[0]
		m.FullScanErrs = m.FullScanErrs[1:]
	}
	return res, err
}

// Compile-time check that MockClient satisfies Client.
var _ Client = (*MockClient)(nil)
