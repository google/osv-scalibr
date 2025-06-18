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

package velestest

import (
	"testing"

	"github.com/google/osv-scalibr/veles"
)

// FakeStringSecret is a fake veles.Secret that contains a string Value.
//
// Since types are important in Veles, there is also a FakeIntSecret to be able
// to distinguish two different secret types.
type FakeStringSecret struct {
	Value string
}

// NewFakeStringSecret creates a new FakeStringSecret from a given string.
func NewFakeStringSecret(s string) FakeStringSecret {
	return FakeStringSecret{Value: s}
}

// FakeIntSecret is a fake veles.Secret that contains integer Data.
//
// Since types are important in Veles, there is also a FakeIntSecret to be able
// to distinguish two different secret types.
type FakeIntSecret struct {
	Data int
}

// NewFakeIntSecret creates a new FakeIntSecret from a given int.
func NewFakeIntSecret(i int) FakeIntSecret {
	return FakeIntSecret{Data: i}
}

// FakeSecretsT is a testing helper to conveniently create a slice of
// veles.Secret.
//
// Based on the underlying type of each element of datas, either a
// FakeStringSecret or a FakeIntSecret is created. If the type is neither int
// nor string, t.Fatalf is invoked because this constitutes a violated
// assumption about the environment.
func FakeSecretsT(t *testing.T) func(datas ...any) []veles.Secret {
	return func(datas ...any) []veles.Secret {
		t.Helper()
		var secrets []veles.Secret
		for _, d := range datas {
			switch s := d.(type) {
			case string:
				secrets = append(secrets, NewFakeStringSecret(s))
			case int:
				secrets = append(secrets, NewFakeIntSecret(s))
			default:
				t.Fatalf("expected string or int, got %T", d)
			}
		}
		return secrets
	}
}

// LessFakeSecretT is used to sort a slice containing instances of the above
// fake veles.Secret types.
//
// This way, tests can e.g. encode the notion that the order in which the
// DetectionEngine detects secrets should be seen as non-deterministic and not
// relied upon (see hyrumslaw.com).
//
// The returned function expects the provided veles.Secret instances to have
// underlying type FakeStringSecret or FakeIntSecret, otherwise the t.Fatalf is
// invoked.
func LessFakeSecretT(t *testing.T) func(a, b veles.Secret) bool {
	return func(a veles.Secret, b veles.Secret) bool {
		t.Helper()
		strA, isStrA := a.(FakeStringSecret)
		intA, isIntA := a.(FakeIntSecret)
		strB, isStrB := b.(FakeStringSecret)
		intB, isIntB := b.(FakeIntSecret)
		if !isStrA && !isIntA {
			t.Fatalf("want FakeStringSecret or FakeIntSecret, got %T", a)
		}
		if !isStrB && !isIntB {
			t.Fatalf("want FakeStringSecret or FakeIntSecret, got %T", b)
		}
		if isStrA {
			if isStrB {
				return strA.Value < strB.Value
			}
			return true
		}
		if isIntB {
			return intA.Data < intB.Data
		}
		return false
	}
}
