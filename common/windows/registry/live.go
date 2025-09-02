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

//go:build windows

package registry

import (
	"errors"
	"fmt"
	"strconv"

	winregistry "golang.org/x/sys/windows/registry"
)

// LiveOpener is an opener for the live registry.
type LiveOpener struct{}

// NewLiveOpener creates a new LiveOpener, allowing to open the live registry.
func NewLiveOpener() *LiveOpener {
	return &LiveOpener{}
}

// Open the live registry.
func (o *LiveOpener) Open() (Registry, error) {
	return &LiveRegistry{}, nil
}

// LiveRegistry wraps the windows registry library to provide live parsing of the Windows registry.
type LiveRegistry struct{}

// OpenKey open the requested registry key.
func (o *LiveRegistry) OpenKey(hive string, path string) (Key, error) {
	var winHive winregistry.Key

	switch hive {
	case "HKLM":
		winHive = winregistry.LOCAL_MACHINE
	case "HKCU":
		winHive = winregistry.CURRENT_USER
	case "HKU":
		winHive = winregistry.USERS
	default:
		return nil, fmt.Errorf("unsupported hive: %s", hive)
	}

	key, err := winregistry.OpenKey(winHive, path, winregistry.QUERY_VALUE|winregistry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}

	return &LiveKey{
		key:  &key,
		name: path,
	}, nil
}

// Close closes the registry hive.
// For live keys, this is a no-op.
func (o *LiveRegistry) Close() error {
	return nil
}

// LiveKey wraps a winregistry.Key to provide an implementation of the registry.Key interface.
type LiveKey struct {
	key  *winregistry.Key
	name string
}

// Name returns the name of the key.
func (o *LiveKey) Name() string {
	return o.name
}

// Subkeys returns the opened subkeys of the key.
// NOT SUPPORTED: This method would be too heavy. We can decide to revisit later if a strong use case
// presents itself. Please use a combination of SubkeyNames() and OpenKey() tailored to your use
// case instead.
func (o *LiveKey) Subkeys() ([]Key, error) {
	return nil, errors.New("not implemented on live registry: this method would be too heavy")
}

// SubkeyNames returns the names of the subkeys of the key.
func (o *LiveKey) SubkeyNames() ([]string, error) {
	return o.key.ReadSubKeyNames(0)
}

// Close closes the key.
func (o *LiveKey) Close() error {
	return o.key.Close()
}

// ClassName returns the class name of the key.
// NOT SUPPORTED: This method is not supported on live registry as the library we use does not
// provide this information and we do not have a use case for it.
func (o *LiveKey) ClassName() ([]byte, error) {
	return nil, errors.New("not supported: class name is not supported on live registry")
}

// Value returns the value with the given name.
// The actual value is lazy loaded when Data() is called.
func (o *LiveKey) Value(name string) (Value, error) {
	return &LiveValue{
		name: name,
		key:  o.key,
	}, nil
}

// ValueBytes directly returns the content (as bytes) of the named value.
func (o *LiveKey) ValueBytes(name string) ([]byte, error) {
	value, err := o.Value(name)
	if err != nil {
		return nil, err
	}

	return value.Data()
}

// ValueString directly returns the content (as string) of the named value.
func (o *LiveKey) ValueString(name string) (string, error) {
	value, err := o.Value(name)
	if err != nil {
		return "", err
	}

	return value.DataString()
}

// Values returns the different values contained in the key.
func (o *LiveKey) Values() ([]Value, error) {
	valueNames, err := o.key.ReadValueNames(0)
	if err != nil {
		return nil, err
	}

	var values []Value
	for _, valueName := range valueNames {
		values = append(values, &LiveValue{
			name: valueName,
			key:  o.key,
		})
	}

	return values, nil
}

// LiveValue wraps a winregistry.Value to provide an implementation of the registry.Value interface.
type LiveValue struct {
	name string
	key  *winregistry.Key
}

// Name returns the name of the value.
func (o *LiveValue) Name() string {
	return o.name
}

// Data returns the data contained in the value as bytes.
func (o *LiveValue) Data() ([]byte, error) {
	size, _, err := o.key.GetValue(o.name, nil)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, size)
	if _, _, err = o.key.GetValue(o.name, buffer); err != nil {
		return nil, err
	}

	return buffer, nil
}

// DataString returns the data contained in the value as a string.
func (o *LiveValue) DataString() (string, error) {
	val, valtype, err := o.key.GetStringValue(o.name)
	if (err == nil) || (valtype == winregistry.SZ || valtype == winregistry.EXPAND_SZ) {
		return val, err
	}

	switch valtype {
	case winregistry.DWORD, winregistry.DWORD_BIG_ENDIAN, winregistry.QWORD:
		val, _, err := o.key.GetIntegerValue(o.name)
		return strconv.FormatUint(val, 10), err
	default:
		return "", fmt.Errorf("unsupported value type: %v for value %q", valtype, o.name)
	}
}
