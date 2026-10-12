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
	"crypto/sha256"
	"fmt"
	"sync/atomic"

	"github.com/google/uuid"
)

// IDGenerator is an interface for generating IDs for packages.
type IDGenerator interface {
	// GenerateID generates an ID for the given package.
	GenerateID(pkgName string) (string, error)
}

var instance IDGenerator = &RandomIDGenerator{}

// SetIDGenerator sets the IDGenerator type used by the current process.
//
// Outside of tests, this should only be called during initialization.
func SetIDGenerator(g IDGenerator) {
	instance = g
}

// GetIDGenerator returns the IDGenerator for the current process.
func GetIDGenerator() IDGenerator {
	return instance
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

// sequentialIDCounter is an incrementing counter shared by all sequential generator instances.
var sequentialIDCounter atomic.Uint64

// SequentialIDGenerator generates sequential IDs for packages, based on the package name and a counter.
type SequentialIDGenerator struct{}

// GenerateID generates a sequential ID for the given package.
func (g *SequentialIDGenerator) GenerateID(pkgName string) (string, error) {
	hash := sha256.Sum256([]byte(pkgName))
	return fmt.Sprintf("pkg-%x-%d", hash[:16], sequentialIDCounter.Add(1)), nil
}
