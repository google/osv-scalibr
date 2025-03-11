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

// Package systemreg provides a wrapper around the SYSTEM registry.
package systemreg

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/osv-scalibr/common/windows/registry"
	"golang.org/x/text/encoding/unicode"
)

var (
	syskeyPaths = []string{"JD", "Skew1", "GBG", "Data"}

	errNoCurrentControlSet = errors.New("system hive: failed to find CurrentControlSet")
)

// SystemRegistry is a wrapper around a SYSTEM registry.
type SystemRegistry struct {
	registry.Registry
}

// NewFromFile creates a new SystemRegistry from a file.
// Note that it is the responsibility of the caller to close the registry once it is no longer
// needed.
func NewFromFile(path string) (*SystemRegistry, error) {
	opener := registry.NewOfflineOpener(path)
	reg, err := opener.Open()
	if err != nil {
		return nil, err
	}

	return &SystemRegistry{reg}, nil
}

// Syskey returns the syskey used to decrypt user hashes.
// The syskey is stored as UTF16-le encoded hexadecimal in the class name of the 4 registry keys
// denoted by `syskeyPaths`. Once the hexadecimal is decoded, the result is still obfuscated and
// the order of the bytes needs to be swapped using the indexes detonated in the `transforms` table.
func (s *SystemRegistry) Syskey() ([]byte, error) {
	currentSet, err := s.currentControlSet()
	if err != nil {
		return nil, err
	}

	var syskey string
	currentControlSet := fmt.Sprintf(`ControlSet%03d\Control\Lsa\`, currentSet)
	for _, k := range syskeyPaths {
		key, err := s.OpenKey("HKLM", currentControlSet+k)
		if err != nil {
			return nil, err
		}

		class, err := key.ClassName()
		if err != nil {
			return nil, err
		}

		syskey += string(class)
	}

	decodedKey, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().String(syskey)
	if err != nil {
		return nil, err
	}

	unhexKey, err := hex.DecodeString(decodedKey)
	if err != nil {
		return nil, err
	}

	transforms := []int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}
	var resultKey []byte

	for i := range unhexKey {
		resultKey = append(resultKey, unhexKey[transforms[i]])
	}

	return resultKey, nil
}

func (s *SystemRegistry) currentControlSet() (uint32, error) {
	key, err := s.OpenKey("HKLM", `Select`)
	if err != nil {
		return 0, err
	}

	values, err := key.Values()
	if err != nil {
		return 0, err
	}

	for _, value := range values {
		if value.Name() == "Current" {
			data, err := value.Data()
			if err != nil {
				return 0, err
			}

			return uint32(data[0]), nil
		}
	}

	return 0, errNoCurrentControlSet
}
