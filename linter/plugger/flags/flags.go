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

// Package flags contains logic for handling repeatable flag
package flags

import "fmt"

// List is a slice of strings that implements the flag.Value interface.
// It is designed to be used with flag.Var to allow a flag to be specified
// multiple times, accumulating all values into the list.
type List []string

// String returns the string representation of the list
func (s *List) String() string {
	return fmt.Sprintf("%v", *s)
}

// Set adds a value to the list
func (s *List) Set(value string) error {
	*s = append(*s, value)
	return nil
}
