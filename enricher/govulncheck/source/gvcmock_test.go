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

package source_test

import (
	"context"
	"encoding/json"
	"os"

	"github.com/google/osv-scalibr/enricher/govulncheck/source/internal"
	vulnpb "github.com/ossf/osv-schema/bindings/go/osvschema"
)

// mockGovulncheckClient is the real implementation of govulncheckClient.
type mockGovulncheckClient struct {
	findings    map[string][]*internal.Finding
	err         error
	goAvailable bool
}

func (r *mockGovulncheckClient) RunGovulncheck(_ context.Context, _ string, _ []*vulnpb.Vulnerability, _ string) (map[string][]*internal.Finding, error) {
	return r.findings, r.err
}

func (r *mockGovulncheckClient) GoToolchainAvailable(ctx context.Context) bool {
	return r.goAvailable
}

func newMockGovulncheckClient(findingsJSONPath string, expectedErr error, goAvailable bool) (*mockGovulncheckClient, error) {
	findingsRaw, err := os.ReadFile(findingsJSONPath)
	if err != nil {
		return nil, err
	}

	var findings map[string][]*internal.Finding
	if err := json.Unmarshal(findingsRaw, &findings); err != nil {
		return nil, err
	}

	return &mockGovulncheckClient{
		findings:    findings,
		err:         expectedErr,
		goAvailable: goAvailable,
	}, nil
}
