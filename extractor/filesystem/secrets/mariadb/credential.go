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

package mariadb

import "strings"

// Credentials contains mariadb credentials
type Credentials struct {
	Section  string
	Host     string
	Port     string
	User     string
	Password string
}

func (c *Credentials) setField(key, value string) bool {
	// "Dashes (-) and underscores (_) in option names are interchangeable"
	// ref: https://mariadb.com/docs/server/server-management/install-and-upgrade-mariadb/configuring-mariadb/configuring-mariadb-with-option-files#options
	k := strings.TrimSpace(strings.ToLower(key))
	switch k {
	case "host":
		c.Host = value
	case "user":
		c.User = value
	case "password":
		c.Password = value
	case "port":
		c.Port = value
	default:
		return false
	}
	return true
}

// isSecret returns true if a set of credentials contains a secret
func isSecret(c *Credentials) bool {
	return c.Password != ""
}
