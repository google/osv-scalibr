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

type validator struct {
	cli *http.Client
}

// SetHTTPClient sets the http.Client which the validator uses.
func (v *validator) SetHTTPClient(cli *http.Client) {
	v.cli = cli
}

// NewValidator creates a new Validator that validates Code Catalyst credentials
func NewValidator() veles.Validator[Credentials] {
	return &validator{
		cli: http.DefaultClient,
	}
}

// Validate validates code AWS Code Catalyst Git Basic Auth credentials
func (v *validator) Validate(ctx context.Context, secret Credentials) (veles.ValidationStatus, error) {
	u, err := url.Parse(secret.FullURL)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("error parsing URL: %w", err)
	}

	if !strings.HasSuffix(u.Host, ".codecatalyst.aws") {
		return veles.ValidationFailed, fmt.Errorf("not a valid AWS Code Catalyst host %q", u.Host)
	}

	return gitbasicauth.Validate(
		ctx, v.cli, u,
		gitbasicauth.Credentials{Username: secret.Username, Password: secret.PAT},
	)
}
