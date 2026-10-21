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

// Package corpus loads the per-CVE vulnerability metadata corpus built by
// the reachability project and exposes it as a lookup indexed by OSV ID.
package corpus

import (
	"encoding/json"
	"fmt"
	"os"

	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

// Location is the Jelly-extension `loc` field (sentinel-loc technique).
// Not part of the upstream OSV schema.
type Location struct {
	Filename string    `json:"filename"`
	Start    *Position `json:"start,omitempty"`
	End      *Position `json:"end,omitempty"`
}

// Position is line/column inside a source file.
type Position struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// Entry is one corpus record: an OSV vulnerability augmented with the
// reachability-project's Jelly-pattern fields (loc + patterns).
//
// OSV is the parsed proto; entries returned by Lookup share storage and
// must be treated as read-only. Mutating fields here will affect every
// other holder of the same id's entries.
type Entry struct {
	OSV      *osvpb.Vulnerability
	Loc      *Location
	Patterns []string
}

// rawEntry mirrors the on-disk JSON shape; OSV is held as raw JSON so we
// can hand it to protojson, which handles proto-specific quirks like
// enum-string parsing for Range.Type ("SEMVER" → Range_SEMVER).
type rawEntry struct {
	OSV      json.RawMessage `json:"osv"`
	Loc      *Location       `json:"loc,omitempty"`
	Patterns []string        `json:"patterns,omitempty"`
}

// MarshalJSON serializes Entry back to the on-disk shape, using protojson
// for the OSV portion so Range.Type round-trips as a string ("SEMVER")
// rather than the proto integer. Jelly's --vulnerabilities consumer
// expects the string form.
func (e Entry) MarshalJSON() ([]byte, error) {
	osvJSON, err := protojson.Marshal(e.OSV)
	if err != nil {
		return nil, fmt.Errorf("marshal osv: %w", err)
	}
	return json.Marshal(rawEntry{OSV: osvJSON, Loc: e.Loc, Patterns: e.Patterns})
}

// Corpus is the loaded metadata, indexed by OSV id.
type Corpus struct {
	byID map[string][]Entry
}

// Load reads and parses a corpus.json file produced by the reachability
// project's build step.
func Load(path string) (*Corpus, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read corpus: %w", err)
	}

	var raws []rawEntry
	if err := json.Unmarshal(data, &raws); err != nil {
		return nil, fmt.Errorf("parse corpus: %w", err)
	}

	c := &Corpus{byID: make(map[string][]Entry, len(raws))}
	for i, r := range raws {
		v := &osvpb.Vulnerability{}
		if err := protojson.Unmarshal(r.OSV, v); err != nil {
			return nil, fmt.Errorf("corpus entry %d: parse osv: %w", i, err)
		}
		defaultRangeType(v)
		id := v.GetId()
		if id == "" {
			return nil, fmt.Errorf("corpus entry %d: missing osv.id", i)
		}
		if len(r.Patterns) == 0 && r.Loc == nil {
			return nil, fmt.Errorf("corpus entry %d (%s): must have patterns[] or loc", i, id)
		}
		c.byID[id] = append(c.byID[id], Entry{OSV: v, Loc: r.Loc, Patterns: r.Patterns})
	}
	return c, nil
}

// defaultRangeType fills Range.Type = SEMVER on any range the corpus author
// left implicit. Without this the proto enum defaults to UNSPECIFIED and
// protojson.Marshal silently omits "type" when we hand the entry back to
// Jelly's --vulnerabilities consumer, which expects the string form.
// SEMVER is the only sensible default for npm — the only ecosystem this
// enricher targets.
func defaultRangeType(v *osvpb.Vulnerability) {
	for _, a := range v.GetAffected() {
		for _, r := range a.GetRanges() {
			if r != nil && r.GetType() == osvpb.Range_UNSPECIFIED {
				r.Type = osvpb.Range_SEMVER
			}
		}
	}
}

// Lookup returns the entries for the given OSV id, or (nil, false) if none.
func (c *Corpus) Lookup(osvID string) ([]Entry, bool) {
	es, ok := c.byID[osvID]
	return es, ok && len(es) > 0
}

// Size returns the total number of entries across all ids.
func (c *Corpus) Size() int {
	n := 0
	for _, es := range c.byID {
		n += len(es)
	}
	return n
}
