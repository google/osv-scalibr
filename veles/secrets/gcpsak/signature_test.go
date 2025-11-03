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

package gcpsak_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles/secrets/gcpsak"
)

func TestSign(t *testing.T) {
	want := exampleSignature
	got := gcpsak.Sign(examplePrivateKey)
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("Sign() diff (-want +got):\n%s", diff)
	}
}

func TestValid(t *testing.T) {
	valid, err := gcpsak.Valid(exampleSignature, exampleCertificate)
	if err != nil {
		t.Errorf("Valid() error: %v, want nil", err)
	}
	if !valid {
		t.Error("Valid() = false, want true")
	}
}

func TestSignature_roundtrip(t *testing.T) {
	randKey, randCert := genKeyAndCert(t)
	cases := []struct {
		name string
		key  string
		cert string
	}{
		{
			name: "constant_examples",
			key:  examplePrivateKey,
			cert: exampleCertificate,
		},
		{
			name: "randomly_generated",
			key:  randKey,
			cert: randCert,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sig := gcpsak.Sign(tc.key)
			if len(sig) == 0 {
				t.Error("Sign() failed")
			}
			valid, err := gcpsak.Valid(sig, tc.cert)
			if err != nil {
				t.Errorf("Valid() error: %v, want nil", err)
			}
			if !valid {
				t.Error("Valid() = false, want true")
			}
		})
	}
}
