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

// Package samreg provides a wrapper around the SAM registry.
package samreg

import (
	"errors"
	"fmt"

	"github.com/google/osv-scalibr/common/windows/registry"
)

const (
	samRegistryPathUsers   = `SAM\Domains\Account\Users`
	samRegistryPathDomains = `SAM\Domains\Account`
)

var (
	errFailedToParseUsers   = errors.New("SAM hive: failed to parse users")
	errFailedToParseDomainF = errors.New("SAM hive: failed to parse domain F structure")
	errFailedToOpenDomain   = errors.New("SAM hive: failed to open the account domain registry")
)

// SAMRegistry is a wrapper around a loaded SAM registry.
type SAMRegistry struct {
	registry.Registry
}

// NewFromFile creates a new SAMRegistry from a file.
// Note that it is the responsibility of the caller to close the registry once it is no longer
// needed.
func NewFromFile(path string) (*SAMRegistry, error) {
	opener := registry.NewOfflineOpener(path)
	reg, err := opener.Open()
	if err != nil {
		return nil, err
	}

	return &SAMRegistry{reg}, nil
}

// UsersRIDs returns the list of local user RIDs.
func (s *SAMRegistry) UsersRIDs() ([]string, error) {
	key, err := s.OpenKey("HKLM", samRegistryPathUsers)
	if err != nil {
		return nil, errFailedToParseUsers
	}

	users := []string{}
	subkeys, err := key.Subkeys()
	if err != nil {
		return nil, err
	}

	for _, subkey := range subkeys {
		if subkey.Name() == "Names" {
			continue
		}

		users = append(users, subkey.Name())
	}

	return users, nil
}

// UserInfo returns the UserInfo for a given user RID.
func (s *SAMRegistry) UserInfo(userRID string) (*UserInfo, error) {
	keyPath := fmt.Sprintf(`%s\%s`, samRegistryPathUsers, userRID)
	key, err := s.OpenKey("HKLM", keyPath)
	if err != nil {
		return nil, fmt.Errorf("SAM hive: failed to load user registry for RID %q", userRID)
	}

	values, err := key.Values()
	if err != nil {
		return nil, err
	}

	var userV *userV
	var userF *userF
	for _, value := range values {
		if userV != nil && userF != nil {
			break
		}

		if value.Name() == "V" {
			data, err := value.Data()
			if err != nil {
				return nil, err
			}

			if userV, err = newUserV(data, userRID); err != nil {
				return nil, err
			}
		}

		if value.Name() == "F" {
			data, err := value.Data()
			if err != nil {
				return nil, err
			}

			userF = newUserF(data, userRID)
		}
	}

	if userV == nil || userF == nil {
		return nil, fmt.Errorf("SAM hive: failed to find V or F structures for RID %q", userRID)
	}

	return &UserInfo{
		rid:   userRID,
		userV: userV,
		userF: userF,
	}, nil
}

// DeriveSyskey loads the domain F structure from the SAM hive and then uses it to derive the
// syskey.
func (s *SAMRegistry) DeriveSyskey(syskey []byte) ([]byte, error) {
	key, err := s.OpenKey("HKLM", samRegistryPathDomains)
	if err != nil {
		return nil, errFailedToOpenDomain
	}

	values, err := key.Values()
	if err != nil {
		return nil, err
	}

	for _, value := range values {
		if value.Name() == "F" {
			data, err := value.Data()
			if err != nil {
				return nil, err
			}

			return newDomainF(data).DeriveSyskey(syskey)
		}
	}

	return nil, errFailedToParseDomainF
}
