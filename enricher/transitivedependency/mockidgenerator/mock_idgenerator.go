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

// Package mockidgenerator provides a mock implementation of the IDGenerator interface.
package mockidgenerator

// MockIDGenerator generates dummy IDs for packages.
type MockIDGenerator struct{}

// GenerateID generates a dummy ID for the given package.
func (g *MockIDGenerator) GenerateID(pkgName string) (string, error) {
	return "dummy-id-" + pkgName, nil
}
