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
	"errors"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/velestest"
)

func TestAcceptValidator(t *testing.T) {
	brokenValidator := velestest.NewFakeValidator[velestest.FakeStringSecret](veles.ValidationFailed, errors.New("service unreachable"))
	relaxedValidator := velestest.NewFakeValidator[velestest.FakeStringSecret](veles.ValidationInvalid, nil)

	velestest.AcceptValidator(
		t,
		relaxedValidator,
		velestest.WithBrokenTransport(brokenValidator),
		velestest.WithTrueNegatives(velestest.FakeStringSecret{Value: "test-invalid"}),
	)
}
