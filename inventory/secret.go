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

package inventory

import (
	"time"

	"github.com/google/osv-scalibr/veles"
)

// Secret (i.e. a credential) found via the Veles secret scanning library.
// Scalibr handles secrets transparently, only Veles cares about what concrete
// type they are.
type Secret struct {
	Secret   veles.Secret
	Location string

	Validation SecretValidationResult
}

// SecretValidationResult is the result of validating a given Secret with the
// corresponding Veles Validator via Enrichment.
type SecretValidationResult struct {
	// At is the time at which the validation was performed.
	At time.Time
	// Status is the ValidationStatus obtained from the Validation.
	Status veles.ValidationStatus
	// Err is only set in case Status is ValidationFailed. In that case, it
	// contains the error encountered during validation.
	Err error
}
