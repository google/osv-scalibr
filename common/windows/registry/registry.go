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

// Package registry provides an interface to abstract the Windows registry libraries away.
// This allows providing more functionalities to registry libraries and also provide a better means
// of testing.
package registry

// Opener is an interface to be able to open an actual registry.
// It was implemented as a way to delay the time between configuring and closing/using the registry.
type Opener interface {
	Open() (Registry, error)
}

// Registry represents an open registry hive.
type Registry interface {
	// OpenKey returns a Key for the given path in a specific hive.
	OpenKey(hive string, path string) (Key, error)

	// Close closes the registry hive.
	Close() error
}

// Key represents a specific registry key.
type Key interface {
	// Name returns the name of the key.
	Name() string

	// Close closes the key.
	Close() error

	// ClassName returns the name of the class for the key.
	ClassName() ([]byte, error)

	// Subkeys returns the opened subkeys of the key.
	Subkeys() ([]Key, error)

	// SubkeyNames returns the names of the subkeys of the key.
	SubkeyNames() ([]string, error)

	// Value returns the value with the given name.
	Value(name string) (Value, error)

	// ValueBytes directly returns the content (as bytes) of the named value.
	ValueBytes(name string) ([]byte, error)

	// ValueString directly returns the content (as string) of the named value.
	ValueString(name string) (string, error)

	// Values returns the different values of the key.
	Values() ([]Value, error)
}

// Value represents a value inside a specific key.
type Value interface {
	// Name returns the name of the value.
	Name() string

	// Data returns the data of the value.
	Data() ([]byte, error)

	// DataString returns the data of the value as a string.
	DataString() (string, error)
}
