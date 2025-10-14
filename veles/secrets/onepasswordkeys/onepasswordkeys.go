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

// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package onepasswordkeys contains detectors and validators for
// 1Password credentials.
package onepasswordkeys

// OnePasswordSecretKey is a Veles Secret that holds a 1Password Secret Key.
type OnePasswordSecretKey struct {
	Key string
}

// OnePasswordServiceToken is a Veles Secret that holds a 1Password Service Account Token.
type OnePasswordServiceToken struct {
	Key string
}

// OnePasswordRecoveryCode is a Veles Secret that holds a 1Password Recovery Code.
type OnePasswordRecoveryCode struct {
	Key string
}
