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

package corpus_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/enricher/reachability/javascript/corpus"
)

const twoEntryCorpus = `[
  {
    "osv": {
      "id": "GHSA-fv66-9v8q-g76r",
      "affected": [
        {
          "package": { "ecosystem": "npm", "name": "react-server-dom-webpack" },
          "ranges": [{"events":[{"introduced":"19.0.0"},{"fixed":"19.0.1"}]}]
        }
      ]
    },
    "loc": { "filename": "__jelly_sentinel_suppress_module_wide_sink__" },
    "patterns": ["call <react-server-dom-webpack/**>.{decodeReply}"]
  },
  {
    "osv": {
      "id": "GHSA-j5w5-568x-rq53",
      "affected": [
        { "package": { "ecosystem": "npm", "name": "fake" } }
      ]
    },
    "patterns": ["call <fake>.sink"]
  }
]`

func writeTempCorpus(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "corpus.json")
	if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestLoad_HappyPath(t *testing.T) {
	path := writeTempCorpus(t, twoEntryCorpus)

	c, err := corpus.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	entries, ok := c.Lookup("GHSA-fv66-9v8q-g76r")
	if !ok {
		t.Fatalf("lookup for existing id returned ok=false")
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	if len(entries[0].Patterns) != 1 {
		t.Fatalf("want 1 pattern, got %d", len(entries[0].Patterns))
	}
	if got := entries[0].OSV.GetId(); got != "GHSA-fv66-9v8q-g76r" {
		t.Errorf("OSV.GetId() = %q, want GHSA-fv66-9v8q-g76r", got)
	}

	_, ok = c.Lookup("GHSA-does-not-exist")
	if ok {
		t.Errorf("lookup for missing id returned ok=true")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := corpus.Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Fatal("Load: want error for missing file, got nil")
	}
}

func TestLoad_MalformedJSON(t *testing.T) {
	path := writeTempCorpus(t, `{not json`)
	_, err := corpus.Load(path)
	if err == nil {
		t.Fatal("Load: want error for malformed JSON, got nil")
	}
}

func TestLoad_RejectsEntryWithoutPatternsOrLoc(t *testing.T) {
	path := writeTempCorpus(t, `[{"osv":{"id":"GHSA-x"}}]`)
	_, err := corpus.Load(path)
	if err == nil {
		t.Fatal("Load: want error for entry with no patterns and no loc")
	}
}

func TestLoad_AllowsLocOnly(t *testing.T) {
	path := writeTempCorpus(t, `[{"osv":{"id":"GHSA-x"},"loc":{"filename":"a.js","start":{"line":1,"column":1},"end":{"line":1,"column":2}}}]`)
	c, err := corpus.Load(path)
	if err != nil {
		t.Fatalf("loc-only entry should be valid: %v", err)
	}
	if _, ok := c.Lookup("GHSA-x"); !ok {
		t.Fatal("loc-only entry was dropped")
	}
}

func TestLoad_AllowsPatternsOnly(t *testing.T) {
	path := writeTempCorpus(t, `[{"osv":{"id":"GHSA-x"},"patterns":["call <x>.y"]}]`)
	c, err := corpus.Load(path)
	if err != nil {
		t.Fatalf("patterns-only entry should be valid: %v", err)
	}
	if _, ok := c.Lookup("GHSA-x"); !ok {
		t.Fatal("patterns-only entry was dropped")
	}
}
