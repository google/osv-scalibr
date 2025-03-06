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

package samreg

import "errors"

const (
	userFAccountEnabledOffset = 0x38
)

var (
	errUserFTooShort = errors.New("userF structure is too short")
)

// userF is a lazy-parsed user F structure containing the user's information in the SAM hive.
// Very important: Do not confuse the SAMUSerF and SAMDomainF structures, the first one refers to
// each user's information (is account active, locked, when was password changed, etc.) while the
// second one refers to the domain's information (password policy, portion of the syskey).
// See https://web.archive.org/web/20190717124313/http://www.beginningtoseethelight.org/ntsecurity/index.htm#8603CF0AFBB170DD
// for more information about the F user structure.
type userF struct {
	buffer []byte
	rid    string
}

// newUserF creates a new lazy-parsed F structure from the SAM hive.
func newUserF(data []byte, rid string) *userF {
	return &userF{
		buffer: data,
		rid:    rid,
	}
}

// Enabled returns whether the user is enabled or not.
func (s *userF) Enabled() (bool, error) {
	if len(s.buffer) < userFAccountEnabledOffset+1 {
		return false, errUserFTooShort
	}

	return (s.buffer[userFAccountEnabledOffset] & 0x01) == 0x00, nil
}
