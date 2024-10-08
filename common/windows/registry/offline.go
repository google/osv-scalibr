// Copyright 2024 Google LLC
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

package registry

import (
	"errors"
	"io"
	"os"

	"www.velocidex.com/golang/regparser"
)

var (
	errFailedToReadClassName = errors.New("failed to read class name")
)

// OfflineRegistry wraps the regparser library to provide offline (from file) parsing of the Windows
// registry.
type OfflineRegistry struct {
	registry *regparser.Registry
	reader   io.ReadCloser
}

// NewFromFile creates a new offline registry abstraction from a file.
func NewFromFile(path string) (*OfflineRegistry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	reg, err := regparser.NewRegistry(f)
	if err != nil {
		f.Close()
		return nil, err
	}

	return &OfflineRegistry{reg, f}, nil
}

// OpenKey open the requested registry key.
func (o *OfflineRegistry) OpenKey(path string) Key {
	return &OfflineKey{o.registry.OpenKey(path)}
}

// Close closes the underlying reader.
func (o *OfflineRegistry) Close() error {
	return o.reader.Close()
}

// OfflineKey wraps a regparser.CM_KEY_NODE to provide an implementation of the registry.Key
// interface.
type OfflineKey struct {
	key *regparser.CM_KEY_NODE
}

// Name returns the name of the key.
func (o *OfflineKey) Name() string {
	return o.key.Name()
}

// Subkeys returns the subkeys of the key.
func (o *OfflineKey) Subkeys() []Key {
	var subkeys []Key
	for _, subkey := range o.key.Subkeys() {
		subkeys = append(subkeys, &OfflineKey{subkey})
	}

	return subkeys
}

// ClassName returns the class name of the key.
func (o *OfflineKey) ClassName() ([]byte, error) {
	// retrieve the class name offset and skip both the first block and the first 4 bytes that
	// represents the size of the block.
	classOffset := int64(o.key.Class()) + 4096 + 4
	classLen := o.key.ClassLength()
	buffer := make([]byte, classLen)

	if n, err := o.key.Reader.ReadAt(buffer, classOffset); err != nil || n != int(classLen) {
		return nil, errFailedToReadClassName
	}

	return buffer, nil
}

// Values returns the different values contained in the key.
func (o *OfflineKey) Values() []Value {
	var values []Value
	for _, value := range o.key.Values() {
		values = append(values, &OfflineValue{value})
	}

	return values
}

// OfflineValue wraps a regparser.CM_KEY_VALUE to provide an implementation of the registry.Value
// interface.
type OfflineValue struct {
	value *regparser.CM_KEY_VALUE
}

// Name returns the name of the value.
func (o *OfflineValue) Name() string {
	return o.value.ValueName()
}

// Data returns the data contained in the value.
func (o *OfflineValue) Data() []byte {
	return o.value.ValueData().Data
}
