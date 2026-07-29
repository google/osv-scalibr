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

package extractor

import (
	"fmt"

	"github.com/google/uuid"
)

// IDGenerator is an interface for generating IDs for packages.
type IDGenerator interface {
	// GenerateID generates an ID for the given package.
	GenerateID(pkgName string) (string, error)
}

// RandomIDGenerator generates random UUIDs for packages.
type RandomIDGenerator struct{}

// GenerateID generates a random UUID for the given package.
func (g *RandomIDGenerator) GenerateID(pkgName string) (string, error) {
	randomID, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("failed to generate random UUID: %w", err)
	}
	return randomID.String(), nil
}
