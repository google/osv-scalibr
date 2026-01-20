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

package source

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/google/osv-scalibr/enricher/govulncheck/source/internal"
	"github.com/google/osv-scalibr/enricher/govulncheck/source/internal/url"
	vulnpb "github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/vuln/scan"
	"google.golang.org/protobuf/encoding/protojson"
)

// realGovulncheckClient is the real implementation of govulncheckClient.
type realGovulncheckClient struct{}

func (r *realGovulncheckClient) RunGovulncheck(ctx context.Context, absModDir string, vulns []*vulnpb.Vulnerability, goVersion string) (map[string][]*internal.Finding, error) {
	// Create a temporary directory containing all the vulnerabilities that
	// are passed in to check against govulncheck.
	//
	// This enables OSV scanner to supply the OSV vulnerabilities to run
	// against govulncheck and manage the database separately from vuln.go.dev.
	dbdir, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, err
	}
	defer func() {
		rerr := os.RemoveAll(dbdir)
		if err == nil {
			err = rerr
		}
	}()

	for _, vuln := range vulns {
		dat, err := protojson.Marshal(vuln)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(fmt.Sprintf("%s/%s.json", dbdir, vuln.GetId()), dat, 0600); err != nil {
			return nil, err
		}
	}

	// this only errors if the file path is not absolute,
	// which paths from os.MkdirTemp should always be
	dbdirURL, err := url.FromFilePath(dbdir)
	if err != nil {
		return nil, err
	}

	// Run govulncheck on the module at moddir and vulnerability database that
	// was just created.
	cmd := scan.Command(ctx, "-db", dbdirURL.String(), "-C", absModDir, "-json", "-mode", "source", "./...")
	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Env = append(os.Environ(), "GOVERSION=go"+goVersion)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}

	// Group the output of govulncheck based on the OSV ID.
	h := &osvHandler{
		idToFindings: map[string][]*internal.Finding{},
	}
	if err := handleJSON(bytes.NewReader(b.Bytes()), h); err != nil {
		return nil, err
	}

	return h.idToFindings, nil
}

func (r *realGovulncheckClient) GoToolchainAvailable(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "go", "version")
	_, err := cmd.Output()

	return err == nil
}
