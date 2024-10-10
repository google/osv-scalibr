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

// Package samreg provides a wrapper around the SAM registry.
package samreg

import (
	"fmt"

	"github.com/google/osv-scalibr/common/windows/registry"
)

const (
	samRegistryPathUsers   = `SAM\Domains\Account\Users`
	samRegistryPathDomains = `SAM\Domains\Account`
)

var (
	errFailedToParseUsers   = fmt.Errorf("SAM hive: failed to parse users")
	errFailedToParseDomainF = fmt.Errorf("SAM hive: failed to parse domain F structure")
	errFailedToOpenDomain   = fmt.Errorf("SAM hive: failed to open the account domain registry")
)

// SAMRegistry is a wrapper around a loaded SAM registry.
type SAMRegistry struct {
	registry.Registry
}

// NewFromFile creates a new SAMRegistry from a file.
func NewFromFile(path string) (*SAMRegistry, error) {
	reg, err := registry.NewFromFile(path)
	if err != nil {
		return nil, err
	}

	return &SAMRegistry{reg}, nil
}

// UsersRIDs returns the list of local user RIDs.
func (s *SAMRegistry) UsersRIDs() ([]string, error) {
	key := s.OpenKey(samRegistryPathUsers)
	if key == nil {
		return nil, errFailedToParseUsers
	}

	users := []string{}
	for _, subkey := range key.Subkeys() {
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
	key := s.OpenKey(keyPath)
	if key == nil {
		return nil, fmt.Errorf("SAM hive: failed to load user registry for RID %q", userRID)
	}

	var userV *UserV
	var userF *UserF
	var err error
	for _, value := range key.Values() {
		if userV != nil && userF != nil {
			break
		}

		if value.Name() == "V" {
			if userV, err = NewUserV(value.Data(), userRID); err != nil {
				return nil, err
			}
		}

		if value.Name() == "F" {
			userF = NewUserF(value.Data(), userRID)
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
	key := s.OpenKey(samRegistryPathDomains)
	if key == nil {
		return nil, errFailedToOpenDomain
	}

	var domainF *DomainF
	for _, value := range key.Values() {
		if value.Name() == "F" {
			domainF = NewDomainF(value.Data())
			break
		}
	}

	if domainF == nil {
		return nil, errFailedToParseDomainF
	}

	return domainF.DeriveSyskey(syskey)
}
