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

package jdbcurlcreds

import (
	"context"
	"net"
	"time"

	"github.com/google/osv-scalibr/veles"
)

const (
	// dnsTimeout is the maximum time to wait for DNS resolution.
	dnsTimeout = 5 * time.Second
)

// Validator validates JDBC URL credentials by checking if the database host
// is publicly accessible. This helps differentiate between credentials for
// local development databases (low risk) and remote/production databases
// (high risk).
type Validator struct {
	Resolver *net.Resolver
}

// NewValidator returns a JDBC URL credentials validator.
func NewValidator() veles.Validator[Credentials] {
	return &Validator{
		Resolver: net.DefaultResolver,
	}
}

// Validate checks whether the JDBC URL credential is for a publicly accessible
// database. Credentials for local/private databases return ValidationFailed
// (not a security risk). Credentials for remote databases return ValidationOK.
func (v *Validator) Validate(ctx context.Context, secret Credentials) (veles.ValidationStatus, error) {
	if !secret.IsRemoteHost {
		return veles.ValidationInvalid, nil
	}

	host := secret.Host

	// If the host is already a public IP, it's confirmed remote.
	if ip := net.ParseIP(host); ip != nil {
		return veles.ValidationValid, nil
	}

	// For hostnames, resolve to IP and verify at least one is public.
	resolveCtx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()

	ips, err := v.Resolver.LookupIPAddr(resolveCtx, host)
	if err != nil {
		// DNS resolution failed — we can't confirm the host is accessible.
		// The detector already flagged it as remote (hostname != localhost),
		// so we return ValidationValid to err on the side of reporting.
		return veles.ValidationValid, nil
	}

	for _, ip := range ips {
		if !ip.IP.IsLoopback() && !ip.IP.IsPrivate() && !ip.IP.IsLinkLocalUnicast() {
			return veles.ValidationValid, nil
		}
	}

	// All resolved IPs are private/loopback.
	return veles.ValidationInvalid, nil
}
