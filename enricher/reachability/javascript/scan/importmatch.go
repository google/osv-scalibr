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

package scan

import (
	"regexp"
	"strings"
	"sync"

	"github.com/google/osv-scalibr/enricher/reachability/javascript/jelly"
)

var moduleTokenRegex = regexp.MustCompile(`<([^>]+)>`)

// globRegexCache memoizes compiled glob→regex translations so that
// AccessPathReachable, called on the hot Phase 1 path once per
// (vuln × pattern × reachable-package), doesn't recompile the same
// regex thousands of times per scan.
var globRegexCache sync.Map // map[string]*regexp.Regexp

// AccessPathReachable reports whether every <module> token in accessPath
// maps to at least one reachable package (by name, subpath prefix, or glob).
// Pruning a vuln requires every token to miss; any-match keeps the vuln
// in scope for the deep Phase 2 scan.
func AccessPathReachable(accessPath string, reachable []jelly.ReachablePackage) bool {
	matches := moduleTokenRegex.FindAllStringSubmatch(accessPath, -1)
	if len(matches) == 0 {
		// No <> tokens: we can't decide from import graph alone; assume
		// reachable to be safe (the full scan will decide).
		return true
	}
	for _, m := range matches {
		token := m[1]
		if !tokenHasMatch(token, reachable) {
			return false
		}
	}
	return true
}

// tokenHasMatch returns true if the <> token matches at least one reachable
// package. Supports three forms:
//
//  1. Plain name:    "lodash"               → exact match or startswith "lodash/"
//  2. Subpath:       "lodash/some/sub"      → same-prefix as form 1
//  3. Glob with *:   "react-server-dom/**"  → package name matches glob
func tokenHasMatch(token string, reachable []jelly.ReachablePackage) bool {
	hasGlob := strings.ContainsAny(token, "*?{")
	if hasGlob {
		re := globToRegex(token)
		for _, p := range reachable {
			if re.MatchString(p.Name) {
				return true
			}
		}
		return false
	}
	// Plain / subpath: take the first path segment (or all of token if
	// there's no /). The reachable package name is what we compare against.
	// Anything matching `name` or starting with `name/` counts.
	name, _, _ := strings.Cut(token, "/")
	for _, p := range reachable {
		if p.Name == name {
			return true
		}
	}
	return false
}

// globToRegex is a minimal glob translator. Supports `**`, `*`, `?`, and
// brace alternation `{a,b}`. Good enough for vulnerability access paths.
// Results are memoized in globRegexCache.
func globToRegex(glob string) *regexp.Regexp {
	if cached, ok := globRegexCache.Load(glob); ok {
		return cached.(*regexp.Regexp)
	}
	re := buildGlobRegex(glob)
	actual, _ := globRegexCache.LoadOrStore(glob, re)
	return actual.(*regexp.Regexp)
}

// buildGlobRegex compiles a fresh regex from glob.
func buildGlobRegex(glob string) *regexp.Regexp {
	var b strings.Builder
	b.WriteByte('^')
	i := 0
	for i < len(glob) {
		c := glob[i]
		switch c {
		case '/':
			// A slash followed by ** means "this slash and everything after it
			// is optional", so that the glob "pkg/**" also matches "pkg" itself.
			if i+2 < len(glob) && glob[i+1] == '*' && glob[i+2] == '*' {
				b.WriteString(`(?:/.*)?`)
				i += 3
				continue
			}
			b.WriteByte('/')
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				b.WriteString(`.*`)
				i += 2
				continue
			}
			b.WriteString(`[^/]*`)
		case '?':
			b.WriteString(`[^/]`)
		case '{':
			// Convert {a,b,c} → (?:a|b|c). Skip empty braces ({} or {,})
			// to avoid emitting (?:) which would match the empty string
			// and let unrelated reachable packages satisfy the token.
			end := strings.IndexByte(glob[i:], '}')
			if end < 0 {
				b.WriteString(regexp.QuoteMeta(glob[i:]))
				i = len(glob)
				continue
			}
			inside := glob[i+1 : i+end]
			i += end + 1
			if inside == "" {
				continue
			}
			alts := strings.Split(inside, ",")
			nonEmpty := alts[:0]
			for _, a := range alts {
				if a != "" {
					nonEmpty = append(nonEmpty, a)
				}
			}
			if len(nonEmpty) == 0 {
				continue
			}
			b.WriteString(`(?:`)
			for j, a := range nonEmpty {
				if j > 0 {
					b.WriteByte('|')
				}
				b.WriteString(regexp.QuoteMeta(a))
			}
			b.WriteByte(')')
			continue
		default:
			if c == '.' || c == '+' || c == '(' || c == ')' || c == '[' || c == ']' || c == '^' || c == '$' || c == '|' || c == '\\' {
				b.WriteByte('\\')
			}
			b.WriteByte(c)
		}
		i++
	}
	// Allow subpaths: a reachable "foo" also matches "foo/..." imports.
	b.WriteString(`(?:/.*)?$`)
	return regexp.MustCompile(b.String())
}
