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

// Package entrypoints infers Jelly entry-point file/directory paths from a
// project's package.json and tsconfig.json. Returning an empty slice means
// "no inference possible — fall back to whole-project".
package entrypoints

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Infer reads package.json and tsconfig.json at projectRoot and returns a
// deterministic list of entry-point paths suitable for Jelly's positional
// arguments. Paths are absolute and guaranteed to reside within
// projectRoot — `../`-bearing entries that resolve outside are silently
// dropped to prevent a malicious or corrupt package.json from steering
// jelly into reading e.g. /etc/* or sibling-project files. Returns nil
// when no signal is found, in which case the caller should pass nil so
// Jelly defaults to [projectRoot].
func Infer(projectRoot string) []string {
	absRoot, err := filepath.Abs(projectRoot)
	if err != nil {
		absRoot = projectRoot
	}
	absRoot = filepath.Clean(absRoot)
	// Resolve symlinks on the root so a symlinked project dir is compared
	// against its real target. Falls back to absRoot if EvalSymlinks fails
	// (e.g. the dir doesn't exist yet — every entry then also fails the
	// stat below).
	realRoot := absRoot
	if r, err := filepath.EvalSymlinks(absRoot); err == nil {
		realRoot = r
	}
	rootPrefix := realRoot + string(filepath.Separator)
	seen := map[string]bool{}
	var out []string
	add := func(rel string) {
		if rel == "" {
			return
		}
		abs := filepath.Clean(filepath.Join(absRoot, filepath.FromSlash(rel)))
		// Lexical pre-check — cheap reject for obvious `../escapes`.
		if abs != absRoot && !strings.HasPrefix(abs, absRoot+string(filepath.Separator)) {
			return
		}
		// Resolve symlinks before final containment so an in-tree
		// symlink pointing outside (e.g. /proj/cache -> /etc) is caught.
		// When the path doesn't exist yet (a common case for pre-build
		// projects whose `main` references not-yet-generated dist/) the
		// lexical pre-check already proved containment — accept the
		// declared path. Jelly will fail-loudly on missing files but
		// can't escape the project root.
		realAbs, err := filepath.EvalSymlinks(abs)
		switch {
		case err == nil:
			if realAbs != realRoot && !strings.HasPrefix(realAbs, rootPrefix) {
				return
			}
		case errors.Is(err, fs.ErrNotExist):
			realAbs = abs // fall back to lexical containment (already passed)
		default:
			return
		}
		// Dedup on the resolved real path so two symlinks pointing at
		// the same target don't both emit (jelly walks each entry).
		if seen[realAbs] {
			return
		}
		seen[realAbs] = true
		out = append(out, abs)
	}

	for _, p := range fromPackageJSON(projectRoot) {
		add(p)
	}
	for _, p := range fromTSConfig(projectRoot) {
		add(p)
	}
	sort.Strings(out) // deterministic for tests and snapshot comparisons
	return out
}

// fromPackageJSON pulls entry-point hints from a project's package.json:
// the `bin` field (single string or name→path map), and the `main`
// /`exports` fields (library public surface).
func fromPackageJSON(projectRoot string) []string {
	raw, err := os.ReadFile(filepath.Join(projectRoot, "package.json"))
	if err != nil {
		return nil
	}
	var pj struct {
		Bin     json.RawMessage `json:"bin"`
		Main    string          `json:"main"`
		Module  string          `json:"module"`
		Exports json.RawMessage `json:"exports"`
	}
	if err := json.Unmarshal(raw, &pj); err != nil {
		return nil
	}
	var paths []string

	// `bin` is either a string or { name: path }.
	if len(pj.Bin) > 0 {
		var s string
		if json.Unmarshal(pj.Bin, &s) == nil && s != "" {
			paths = append(paths, s)
		} else {
			var m map[string]string
			if json.Unmarshal(pj.Bin, &m) == nil {
				for _, v := range m {
					if v != "" {
						paths = append(paths, v)
					}
				}
			}
		}
	}

	if pj.Main != "" {
		paths = append(paths, pj.Main)
	}
	if pj.Module != "" {
		paths = append(paths, pj.Module)
	}

	// `exports` is recursively-nested string|map. Walk it and collect every
	// string leaf — those are the package's published entry points.
	for _, p := range walkExports(pj.Exports) {
		if p != "" && !strings.HasPrefix(p, "#") {
			paths = append(paths, p)
		}
	}
	return paths
}

// walkExports returns every string leaf inside a package.json "exports"
// value, which may be a string, an array of strings, or a map of strings to
// further exports values (recursive).
func walkExports(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if s == "" {
			return nil
		}
		return []string{s}
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		var out []string
		for _, e := range arr {
			out = append(out, walkExports(e)...)
		}
		return out
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) == nil {
		var out []string
		for _, v := range m {
			out = append(out, walkExports(v)...)
		}
		return out
	}
	return nil
}

// fromTSConfig pulls entry-point hints from tsconfig.json's `files` and
// `include` arrays. `include` entries are passed through as-is — Jelly
// accepts both file paths and directories, and glob-resolving here would
// duplicate Jelly's own walk.
func fromTSConfig(projectRoot string) []string {
	raw, err := os.ReadFile(filepath.Join(projectRoot, "tsconfig.json"))
	if err != nil {
		return nil
	}
	// tsconfig allows comments and trailing commas. Strip line comments
	// only — full JSON5 parsing is overkill for a best-effort hint.
	raw = stripLineComments(raw)
	var tc struct {
		Files   []string `json:"files"`
		Include []string `json:"include"`
	}
	if err := json.Unmarshal(raw, &tc); err != nil {
		return nil
	}
	out := make([]string, 0, len(tc.Files)+len(tc.Include))
	out = append(out, tc.Files...)
	// Drop glob-suffixed include entries like "src/**/*" — pass the prefix
	// directory instead so Jelly's own entry-point walker handles it.
	for _, inc := range tc.Include {
		if i := strings.IndexAny(inc, "*?"); i >= 0 {
			inc = strings.TrimRight(inc[:i], "/")
		}
		if inc != "" {
			out = append(out, inc)
		}
	}
	return out
}

// stripLineComments removes // line comments from a tsconfig.json byte slice.
// It's deliberately string-blind (no awareness of strings containing "//"),
// because tsconfig string values almost never contain // and the worst
// outcome of a false trim is that the file fails to parse and we return nil.
func stripLineComments(b []byte) []byte {
	out := make([]byte, 0, len(b))
	i := 0
	for i < len(b) {
		if i+1 < len(b) && b[i] == '/' && b[i+1] == '/' {
			for i < len(b) && b[i] != '\n' {
				i++
			}
			continue
		}
		out = append(out, b[i])
		i++
	}
	return out
}
