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

// Package flatjson contains facilities to extract credentials that are
// expressed as a single (flat) JSON object whose values are all strings.
//
// This can be use to extract GCP service account keys, GCP API keys, etc.
package flatjson

import (
	"regexp"
	"strings"
)

const (
	// DefaultMaxMatches is the default value for an Extractor's MaxMatches. It is
	// used to limit the number of matches to constrain runtime.
	DefaultMaxMatches = 20
)

var (
	// Matches on top-level JSON string fields at arbitrary levels of escaping.
	// This can be used to reliably extract the fields of a GCP SAK from something
	// matched by reJSON at a higher sensitivity than relying on Go's JSON
	// parsing.
	reExtract = regexp.MustCompile(`[\\"]*"([^"]*)[\\"]*":\s*[\\"]*"([^"]*)[\\"]*",?`)
)

// Extractor extracts key-value pairs with required or optional keys from an
// input. It assumes that the key-value pairs are contained in a flat JSON
// object as it is the case for e.g. GCP service account keys.
type Extractor struct {
	// keysRequired contains all the keys whose values the Extractor should
	// extract from the input.
	// If, for a given key k, keysRequired[k] is true, the key is required: if
	// it's absent from the result or empty, a nil result is returned. Keys for
	// which keysRequired[k] is false are contained in the result if they are
	// present in the input but don't cause a nil result if they are missing.
	keysRequired map[string]bool

	numRequired int

	// MaxMatches limits the number of matches to constrain runtime. The default
	// is 20 but it can be set arbitrarily, even to -1 in which case no limit is
	// applied.
	//
	// For example Although we're expecting only about 10 fields for GCP service
	// account keys, it makes sense to have a slightly larger limit, because
	// fields like "universe" get added to the key or people might add their own
	// metadata to the JSON structure.
	MaxMatches int
}

// NewExtractor creates an Extractor that can be used to extract flat-JSON
// key-value pairs from an input. The requiredKeys take precedence; if a key is
// present in both requiredKeys and optionalKeys (although it really shouldn't
// be), it's considered required.
func NewExtractor(requiredKeys []string, optionalKeys []string) *Extractor {
	e := &Extractor{
		keysRequired: make(map[string]bool, len(requiredKeys)+len(optionalKeys)),
		numRequired:  len(requiredKeys),
		MaxMatches:   DefaultMaxMatches,
	}
	for _, k := range optionalKeys {
		e.keysRequired[k] = false
	}
	for _, k := range requiredKeys {
		e.keysRequired[k] = true
	}
	return e
}

// Extract extracts the required and optional keys alongside their values from
// the flat JSON object contained in data.
func (e *Extractor) Extract(data []byte) map[string]string {
	kv := make(map[string]string, e.numRequired)
	subs := reExtract.FindAllSubmatch(data, e.MaxMatches)
	for _, sub := range subs {
		key := clean(sub[1])
		if _, want := e.keysRequired[key]; !want {
			continue
		}
		kv[key] = clean(sub[2])
	}
	for key, required := range e.keysRequired {
		if !required {
			continue
		}
		value, present := kv[key]
		if !present || value == "" {
			return nil
		}
	}
	return kv
}

// clean removes all levels of escaping from a string containing a flat (one
// level deep) JSON object that can be escaped arbitrarily often.
func clean(s []byte) string {
	if len(s) == 0 {
		return ""
	}
	var b strings.Builder
	skip := false
	for i := range len(s) - 1 {
		if skip {
			skip = false
			continue
		}
		c := s[i]
		if c == '\\' {
			if s[i+1] == 'n' {
				b.WriteByte('\n')
				skip = true
			}
			continue
		}
		b.WriteByte(c)
	}
	if !skip && s[len(s)-1] != '\\' {
		b.WriteByte(s[len(s)-1])
	}
	return b.String()
}
