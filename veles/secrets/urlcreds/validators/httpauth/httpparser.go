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

package httpauth

import (
	"bytes"
	"strings"
)

// parsePairs extracts key/value pairs from a comma-separated list of
// values as described by RFC 2068 and returns a map[key]value. The
// resulting values are unquoted. If a list element doesn't contain a
// "=", the key is the element itself and the value is an empty
// string.
//
// Lifted from // https://github.com/abbot/go-http-auth/blob/b2a0e3997b9abf90cb8f57c0ed079a6f9a8d2849/misc.go#L81C6-L81C16
func parsePairs(value string) map[string]string {
	m := make(map[string]string)
	for _, pair := range parseList(strings.TrimSpace(value)) {
		switch i := strings.Index(pair, "="); {
		case i < 0:
			// No '=' in pair, treat whole string as a 'key'.
			m[pair] = ""
		case i == len(pair)-1:
			// Malformed pair ('key=' with no value), keep key with empty value.
			m[pair[:i]] = ""
		default:
			v := pair[i+1:]
			if v[0] == '"' && v[len(v)-1] == '"' {
				// Unquote it.
				v = v[1 : len(v)-1]
			}
			m[pair[:i]] = v
		}
	}
	return m
}

// parseList parses a comma-separated list of values as described by
// RFC 2068 and returns list elements.
func parseList(value string) []string {
	var list []string
	var escape, quote bool
	b := new(bytes.Buffer)
	for _, r := range value {
		switch {
		case escape:
			b.WriteRune(r)
			escape = false
		case quote:
			if r == '\\' {
				escape = true
			} else {
				if r == '"' {
					quote = false
				}
				b.WriteRune(r)
			}
		case r == ',':
			list = append(list, strings.TrimSpace(b.String()))
			b.Reset()
		case r == '"':
			quote = true
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	// Append last part.
	if s := b.String(); s != "" {
		list = append(list, strings.TrimSpace(s))
	}
	return list
}
