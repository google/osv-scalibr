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

package urlcreds

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/urlcreds/validators"
)

// ProtocolValidator is the interface that groups URL credentials validators.
type ProtocolValidator interface {
	Validate(ctx context.Context, u *url.URL) (veles.ValidationStatus, error)
}

// Validator is a URL credentials validator.
type Validator struct {
	Client *http.Client
}

// NewValidator returns an URL credentials validator.
func NewValidator() veles.Validator[Credentials] {
	return &Validator{
		Client: http.DefaultClient,
	}
}

// Validate checks whether an URL credential is valid by making one or more requests to the target service.
func (v *Validator) Validate(ctx context.Context, secret Credentials) (veles.ValidationStatus, error) {
	u, err := url.Parse(secret.FullURL)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("error parsing the url: %w", err)
	}
	var validator ProtocolValidator
	switch scheme := strings.ToLower(u.Scheme); scheme {
	case "http", "https":
		validator = &validators.HTTPValidator{Client: v.Client}
	case "ftp":
		validator = &validators.FTPValidator{}
	case "sftp":
		validator = &validators.SFTPValidator{}
	default:
		return veles.ValidationFailed, fmt.Errorf("scheme %q not supported", scheme)
	}

	return validator.Validate(ctx, u)
}
