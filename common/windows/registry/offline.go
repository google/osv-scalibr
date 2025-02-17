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

package registry

import (
	"errors"
	"io"
	"os"

	"www.velocidex.com/golang/regparser"
)

var (
	errFailedToReadClassName = errors.New("failed to read class name")
	errFailedToOpenKey       = errors.New("failed to open key")
	errFailedToFindValue     = errors.New("could not find value")
)

// OfflineOpener is an opener for the offline registry.
type OfflineOpener struct {
	Filepath string
}

// NewOfflineOpener creates a new OfflineOpener, allowing to open a registry from a file.
func NewOfflineOpener(filepath string) *OfflineOpener {
	return &OfflineOpener{filepath}
}

// Open the offline registry.
func (o *OfflineOpener) Open() (Registry, error) {
	f, err := os.Open(o.Filepath)
	if err != nil {
		return nil, err
	}

	reg, err := regparser.NewRegistry(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}

	return &OfflineRegistry{reg, f}, nil
}

// OfflineRegistry wraps the regparser library to provide offline (from file) parsing of the Windows
// registry.
type OfflineRegistry struct {
	registry *regparser.Registry
	reader   io.ReadCloser
}

// OpenKey open the requested registry key.
// Note that for offline keys, the hive is not used.
func (o *OfflineRegistry) OpenKey(_ string, path string) (Key, error) {
	key := o.registry.OpenKey(path)
	if key == nil {
		return nil, errFailedToOpenKey
	}

	return &OfflineKey{key: key}, nil
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

// SubkeyNames returns the names of the subkeys of the key.
func (o *OfflineKey) SubkeyNames() ([]string, error) {
	var names []string
	for _, subkey := range o.key.Subkeys() {
		names = append(names, subkey.Name())
	}

	return names, nil
}

// Subkeys returns the subkeys of the key.
func (o *OfflineKey) Subkeys() ([]Key, error) {
	var subkeys []Key
	for _, subkey := range o.key.Subkeys() {
		subkeys = append(subkeys, &OfflineKey{subkey})
	}

	return subkeys, nil
}

// Close closes the key.
// For offline keys, this is a no-op.
func (o *OfflineKey) Close() error {
	return nil
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

// Value returns the value with the given name.
func (o *OfflineKey) Value(name string) (Value, error) {
	for _, value := range o.key.Values() {
		if value.ValueName() == name {
			return &OfflineValue{value}, nil
		}
	}

	return nil, errFailedToFindValue
}

// ValueBytes directly returns the content (as bytes) of the named value.
func (o *OfflineKey) ValueBytes(name string) ([]byte, error) {
	value, err := o.Value(name)
	if err != nil {
		return nil, err
	}

	return value.Data()
}

// ValueString directly returns the content (as string) of the named value.
func (o *OfflineKey) ValueString(name string) (string, error) {
	value, err := o.Value(name)
	if err != nil {
		return "", err
	}

	return value.DataString()
}

// Values returns the different values contained in the key.
func (o *OfflineKey) Values() ([]Value, error) {
	var values []Value
	for _, value := range o.key.Values() {
		values = append(values, &OfflineValue{value})
	}

	return values, nil
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
func (o *OfflineValue) Data() ([]byte, error) {
	return o.value.ValueData().Data, nil
}

// DataString returns the data contained in the value as a string. Note that if the original data
// is not a string it will be converted.
func (o *OfflineValue) DataString() (string, error) {
	return o.value.ValueData().GoString(), nil
}
