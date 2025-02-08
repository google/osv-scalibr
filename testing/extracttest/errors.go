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

package extracttest

import (
	"fmt"
	"strings"
)

// ContainsErrStr is an error that matches other errors that contains
// `str` in their error string.
//
//nolint:errname
type ContainsErrStr struct {
	Str string
}

// Error returns the error string
func (e ContainsErrStr) Error() string { return fmt.Sprintf("error contains: '%s'", e.Str) }

// Is checks whether the input error contains the string in ContainsErrStr
func (e ContainsErrStr) Is(err error) bool {
	return strings.Contains(err.Error(), e.Str)
}
