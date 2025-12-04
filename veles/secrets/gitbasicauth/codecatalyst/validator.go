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

package codecatalyst

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gitbasicauth"
)

// Validator validates CodeCatalyst credentials
type Validator struct {
	cli *http.Client
}

// SetHTTPClient sets the http.Client which the validator uses.
func (v *Validator) SetHTTPClient(cli *http.Client) {
	v.cli = cli
}

// NewValidator creates a new Validator that validates CodeCatalyst credentials
func NewValidator() *Validator {
	return &Validator{
		cli: http.DefaultClient,
	}
}

// Validate validates code AWS CodeCatalyst Git Basic Auth credentials.
func (v *Validator) Validate(ctx context.Context, secret Credentials) (veles.ValidationStatus, error) {
	u, err := url.Parse(secret.FullURL)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("error parsing URL: %w", err)
	}

	// redundant host validation kept intentionally as a security measure in case any regression
	// is introduced in the detector.
	if !strings.HasSuffix(u.Host, ".codecatalyst.aws") {
		return veles.ValidationFailed, fmt.Errorf("not a valid AWS CodeCatalyst host %q", u.Host)
	}

	status, err := gitbasicauth.Info(ctx, v.cli, u)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to reach Git info endpoint: %w", err)
	}

	// Credentials successfully authenticated and repository info retrieved.
	if status == http.StatusOK {
		return veles.ValidationValid, nil
	}

	// Returns credentials invalid for every other state as the CodeCatalyst server always
	// responds with either 200 or 400 status codes
	return veles.ValidationInvalid, nil
}
