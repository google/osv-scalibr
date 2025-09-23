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

package pgpass

import (
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

// maxTokenLength is the extimated maximum size of a pgpass line.
// Following the list of maximium extimated size for each field
// - Hostname (FQDN maximium 255 chars)
// - port (maximium 5 chars)
// - database (extimated max 100 chars (64 by default but can be expanded from config))
// - user (maximum extimated length 100 chars
// - password (maximium extimated length 100 chars)
//
// There is no official documentation about the maximium password length nor about the
// maximum buffer length of a single pgpass entry.
// Checking the source code of postgresql, when parsing the .pgpass file there is
// multiple realloc of 128 bytes until the end of the buffer
// (https://github.com/postgres/postgres/blob/master/src/interfaces/libpq/fe-connect.c)
//
// In addition please see the following file which defines the official length
// of the identifiers (that is 64 chars)
// Reference:
// - https://github.com/postgres/postgres/blob/master/src/include/pg_config_manual.h
const maxTokenLength = 560

// keyRe is a regular expression that matches the content of a pgpass file entry
// Every entry in the pgpass file is composed by the following fields:
// hostname:port:database:username:password
//   - hostname: matches any character except the `:` (that is currently used for separating fields)
//   - port: matches numbers until 5 digits and * (wildcard)
//     this group can match ports > 65535 but it is a compromise for regex performance
//   - database: same as hostname
//   - username: same as hostname
//   - password: can match any allowed characters but semicolon must be escaped and wildcard is not allowed
//
// Official documentation:
// - https://www.postgresql.org/docs/current/libpq-pgpass.html
var keyRe = regexp.MustCompile(`(?m)^(?:[!-9;-~]+):(?:\*|[0-9]{1,5}):(?:[!-9;-~]+):(?:[!-9;-~]+):(?:\\:|[!-9;-~])*(?:\\:|[!-)+-.0-9;-~])(?:\\:|[!-9;-~])*$`)

// NewDetector returns a new simpletoken.Detector that matches a complete entry
// of a .pgpass file for which the related structure is define in the above
// source code.
func NewDetector() veles.Detector {
	return simpletoken.Detector{
		MaxLen: maxTokenLength,
		Re:     keyRe,
		FromMatch: func(b []byte) veles.Secret {
			return Pgpass{Entry: string(b)}
		},
	}
}
