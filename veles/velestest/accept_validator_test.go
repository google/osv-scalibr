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

package velestest_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/velestest"
)

type swappableValidator struct {
	client      *http.Client
	brokenCalls int
}

func (v *swappableValidator) Validate(ctx context.Context, _ velestest.FakeStringSecret) (veles.ValidationStatus, error) {
	if err := ctx.Err(); err != nil {
		return veles.ValidationFailed, err
	}
	if v.client == velestest.BrokenClient {
		v.brokenCalls++
		return veles.ValidationFailed, errors.New("service unreachable")
	}
	return veles.ValidationInvalid, nil
}

func TestAcceptValidator(t *testing.T) {
	client := &http.Client{}
	validator := &swappableValidator{client: client}

	velestest.AcceptValidator(
		t,
		validator,
		velestest.WithTrueNegatives(velestest.FakeStringSecret{Value: "test-invalid"}),
		velestest.WithBrokenTransport(func(v *swappableValidator) {
			v.client = velestest.BrokenClient
		}),
	)

	if validator.brokenCalls != 1 {
		t.Errorf("unreachable-service called Validate %d times with the broken client, want 1", validator.brokenCalls)
	}
}
