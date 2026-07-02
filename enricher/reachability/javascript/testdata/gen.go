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

//go:build ignore

// This file is the code-generator for testdata/corpus.json. Run:
//
//	go run enricher/reachability/javascript/testdata/gen.go
//
// It walks the per-CVE directories under testdata/, concatenates each
// metadata.json into a single array, and writes the result to
// testdata/corpus.json.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	root := "enricher/reachability/javascript/testdata"
	entries, err := os.ReadDir(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read dir:", err)
		os.Exit(1)
	}
	var all []json.RawMessage
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "GHSA-") {
			continue
		}
		meta := filepath.Join(root, e.Name(), "metadata.json")
		raw, err := os.ReadFile(meta)
		if err != nil {
			fmt.Fprintln(os.Stderr, "skip:", meta, err)
			continue
		}
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			fmt.Fprintln(os.Stderr, "parse:", meta, err)
			continue
		}
		all = append(all, arr...)
	}
	out, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(root, "corpus.json"), out, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d entries to %s/corpus.json\n", len(all), root)
}
