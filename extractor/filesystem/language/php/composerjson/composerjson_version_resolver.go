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

package composerjson

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ----- type definitions -----

// stability ranks in composer sort order. stable is 0 so the zero version is a stable release
const (
	stabilityDev    = -4
	stabilityAlpha  = -3
	stabilityBeta   = -2
	stabilityRC     = -1
	stabilityStable = 0
	stabilityPatch  = 1
)

var stabilityNames = map[int]string{
	stabilityDev:   "dev",
	stabilityAlpha: "alpha",
	stabilityBeta:  "beta",
	stabilityRC:    "RC",
	stabilityPatch: "patch",
}

// version is a composer-normalized version with 4 numeric parts and an optional suffix (e.g. -beta1).
type version struct {
	parts     [4]int
	stability int
	// number after the stability (e.g. 1 in beta1). further numbers (e.g. beta1.2) are ignored
	num int
}

// matches up to 4 digits, an optional suffix (e.g. -beta1, -RC2, -p1) and an optional build (e.g. +build5).
// the build is ignored
var versionRe = regexp.MustCompile(`(?i)^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:[._-]?(stable|beta|b|rc|alpha|a|patch|pl|p)((?:[.-]?\d+)*))?([.-]?dev)?(?:\+\S+)?$`)

func (v version) cmp(o version) int {
	for i := range v.parts {
		if v.parts[i] != o.parts[i] {
			if v.parts[i] < o.parts[i] {
				return -1
			}
			return 1
		}
	}
	if v.stability != o.stability {
		if v.stability < o.stability {
			return -1
		}
		return 1
	}
	if v.num != o.num {
		if v.num < o.num {
			return -1
		}
		return 1
	}
	return 0
}

// bump returns v with the digit at index idx incremented and all later digits zeroed.
// the result is an exclusive upper bound, so it gets the dev suffix like in composer (e.g. ^1.2 is <2.0.0.0-dev).
// this excludes the pre-releases of the bumped version
func (v version) bump(idx int) version {
	v.parts[idx]++
	for i := idx + 1; i < len(v.parts); i++ {
		v.parts[i] = 0
	}
	v.stability, v.num = stabilityDev, 0
	return v
}

// devFloor moves a stable v below all of its pre-releases (e.g. 1.2 -> 1.2.0.0-dev), like composer does
// for >= and < bounds. a version with a suffix is kept (e.g. >=1.2-beta2 must not allow beta1):
//   - a >= bound starts at dev. getMinimumVersionForGroup can only raise it to the allowed stability
//     (e.g. >=1.2@beta resolves to 1.2.0-beta, not 1.2.0)
//   - a < bound excludes the pre-releases of its version (e.g. <2.0 excludes 2.0.0-beta1)
//
// the allowed stability is not applied here. it comes from the whole constraint
// (e.g. the @beta in ^1.2 || ^2.0@beta), and parseConstraint sees one token only
func (v version) devFloor() version {
	if v.stability == stabilityStable {
		v.stability = stabilityDev
	}
	return v
}

func (v version) holds(p comparator) bool {
	c := v.cmp(p.v)
	switch p.op {
	case "==":
		return c == 0
	case "!=":
		return c != 0
	case ">":
		return c > 0
	case ">=":
		return c >= 0
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	}
	return false
}

// next returns the successor of v. stable versions step the 4th digit (e.g. 1.0.0 -> 1.0.0.1).
// suffixed versions step the suffix number (e.g. beta1 -> beta2). this is an approximation,
// composer also sorts versions like beta1.1 in between
func (v version) next() version {
	if v.stability == stabilityStable {
		v.parts[3]++
	} else {
		v.num++
	}
	return v
}

// String prints the 4th digit only when non-zero, also with a suffix (e.g. 1.2.3-patch1, not 1.2.3.0-patch1).
// advisories use the short form, and version_compare sorts 1.2.3.0-beta1 above 1.2.3
func (v version) String() string {
	parts := []string{strconv.Itoa(v.parts[0]), strconv.Itoa(v.parts[1]), strconv.Itoa(v.parts[2])}
	if v.parts[3] != 0 {
		parts = append(parts, strconv.Itoa(v.parts[3]))
	}
	s := strings.Join(parts, ".")
	if v.stability != stabilityStable {
		s += "-" + stabilityNames[v.stability]
		if v.num != 0 {
			s += strconv.Itoa(v.num)
		}
	}
	return s
}

// comparator is one primitive comparison; a constraint parses to an OR-list of AND-groups of these.
type comparator struct {
	op string
	v  version
}

// ----- helper functions -----

var suffixNumRe = regexp.MustCompile(`\d+`)

// parseDigits parses a version string, returning the normalized version
// and how many components were given (1-4).
func parseDigits(s string) (version, int, error) {
	m := versionRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return version{}, 0, fmt.Errorf("cannot parse version %q", s)
	}
	var v version
	n := 0
	for i, g := range m[1:5] {
		if g != "" {
			v.parts[i], _ = strconv.Atoi(g)
			n++
		}
	}

	switch strings.ToLower(m[5]) {
	case "alpha", "a":
		v.stability = stabilityAlpha
	case "beta", "b":
		v.stability = stabilityBeta
	case "rc":
		v.stability = stabilityRC
	case "patch", "pl", "p":
		v.stability = stabilityPatch
	}
	// a stable suffix is the release itself (e.g. 1.0.0-stable1 is 1.0.0), so its number is ignored
	if num := suffixNumRe.FindString(m[6]); num != "" && v.stability != stabilityStable {
		v.num, _ = strconv.Atoi(num)
	}
	// a dev suffix (m[7]) is ignored. composer adds it to >= and < bounds anyway,
	// so the range of >=1.0-dev is the same as >=1.0. its effect on the allowed stability
	// is handled in allowedStability
	return v, n, nil
}

// ----- version resolver -----

var (
	matchAllRe = regexp.MustCompile(`(?i)^v?[x*](\.[x*])*$`)
	xRangeRe   = regexp.MustCompile(`(?i)^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.[x*])+$`)
	cmpRe      = regexp.MustCompile(`^(<>|!=|>=|<=|==|=|>|<)\s*(.+)$`)
	hyphenRe   = regexp.MustCompile(`(\S+)\s+-\s+(\S+)`)
	orRe       = regexp.MustCompile(`\s*\|\|?\s*`)
	andRe      = regexp.MustCompile(`[\s,]+`)
	opSpaceRe  = regexp.MustCompile(`([<>=])\s+`)
	flagRe     = regexp.MustCompile(`(?i)@(stable|rc|beta|alpha|dev)\b`)
)

func parseHyphenComparators(from, to string) ([]comparator, error) {
	fromVersion, _, err := parseDigits(from)
	if err != nil {
		return nil, err
	}
	toVersion, toVersionN, err := parseDigits(to)
	if err != nil {
		return nil, err
	}
	comparators := []comparator{{">=", fromVersion.devFloor()}}
	// upper bound is fully specified. inclusive comparison
	if toVersionN >= 3 {
		return append(comparators, comparator{"<=", toVersion}), nil
	}
	// upper bound not fully specified. exclusive comparison
	idx := 0
	if toVersionN >= 2 {
		idx = 1
	}
	return append(comparators, comparator{"<", toVersion.bump(idx)}), nil
}

func parseConstraint(token string) ([]comparator, error) {
	// match-all: (*.*.*)
	if matchAllRe.MatchString(token) {
		return nil, nil
	}

	// tilde range: the last given digit may float
	if strings.HasPrefix(token, "~") {
		v, n, err := parseDigits(token[1:])
		if err != nil {
			return nil, err
		}

		// calculate the index of the last given digit of the version string
		// used to bump the version for the upper bound
		idx := max(0, n-2) // lastPosition = max(1, position-1)
		return []comparator{
			{">=", v.devFloor()},
			{"<", v.bump(idx)},
		}, nil
	}

	// caret range: update to the next compatibility boundary. upper-bound is defined by:
	//   * bumping the leftmost non-zero digit
	//   * if the version is < 1.0, bumping the left-most non-zero digit
	//   * if constraint is unspecified (e.g. ^0 or ^0.0), bumping the right-most zero
	if strings.HasPrefix(token, "^") {
		v, n, err := parseDigits(token[1:])
		if err != nil {
			return nil, err
		}

		// look for the left-most non-zero to bump
		// if none found, bump the last supplied
		idx := n - 1
		for i := range n {
			if v.parts[i] != 0 {
				idx = i
				break
			}
		}

		return []comparator{
			{">=", v.devFloor()},
			{"<", v.bump(idx)},
		}, nil
	}

	// exclusive range: 1.2.* is sugar for >=1.2.0.0 <1.3.0.0
	if m := xRangeRe.FindStringSubmatch(token); m != nil {
		var low version
		n := 0
		for i, g := range m[1:4] {
			if g != "" {
				low.parts[i], _ = strconv.Atoi(g)
				n++
			}
		}
		high := low.bump(n - 1)
		if low == (version{}) {
			return []comparator{{"<", high}}, nil
		}
		return []comparator{{">=", low.devFloor()}, {"<", high}}, nil
	}

	// basic comparators
	if m := cmpRe.FindStringSubmatch(token); m != nil {
		op := m[1]
		switch op {
		case "=", "==":
			op = "=="
		case "<>":
			op = "!="
		}
		v, _, err := parseDigits(m[2])
		if err != nil {
			return nil, err
		}
		if op == "<" || op == ">=" {
			v = v.devFloor()
		}
		return []comparator{{op, v}}, nil
	}

	// bare version = exact match, normalized to 4 parts
	v, _, err := parseDigits(token)
	if err != nil {
		return nil, err
	}
	return []comparator{{"==", v}}, nil
}

// parseConstraints processes a given version constraint string
// returns a multi-dimensional array containing the disjunctive normal form (dnf) of the constraint
func parseConstraints(constraint string) ([][]comparator, error) {
	var dnf [][]comparator

	// process OR branches
	for _, orBranch := range orRe.Split(strings.TrimSpace(constraint), -1) {
		var comparators []comparator

		// remove stability flags (e.g. @dev). they only affect which releases are installable
		orBranch = flagRe.ReplaceAllString(orBranch, "")

		// process hyphenated comparators (e.g. 1.0 - 2.0)
		for _, match := range hyphenRe.FindAllStringSubmatch(orBranch, -1) {
			p, err := parseHyphenComparators(match[1], match[2])
			if err != nil {
				return nil, err
			}
			comparators = append(comparators, p...)
		}

		rest := hyphenRe.ReplaceAllString(orBranch, " ")

		// remove whitespace after operators (e.g. >= 1.0) so the AND split keeps them together
		rest = opSpaceRe.ReplaceAllString(rest, "$1")

		// process AND branches
		for _, andBranch := range andRe.Split(strings.TrimSpace(rest), -1) {
			if andBranch == "" {
				continue
			}

			p, err := parseConstraint(andBranch)
			if err != nil {
				return nil, err
			}
			comparators = append(comparators, p...)
		}

		dnf = append(dnf, comparators)
	}
	return dnf, nil
}

var flagStabilities = map[string]int{
	"stable": stabilityStable,
	"rc":     stabilityRC,
	"beta":   stabilityBeta,
	"alpha":  stabilityAlpha,
	"dev":    stabilityDev,
}

// allowedStability returns the least stable release a constraint allows. composer applies it to the whole package:
//   - explicit flags (e.g. @beta) win. the least stable one is used
//   - otherwise it is inferred from suffixes (e.g. ^2.0-beta1 allows beta, >=1.0-dev allows dev)
//   - hyphen ranges are only checked for flags, like in composer
func allowedStability(constraint string) int {
	var tokens []string
	for _, orBranch := range orRe.Split(strings.TrimSpace(constraint), -1) {
		tokens = append(tokens, hyphenRe.FindAllString(orBranch, -1)...)
		rest := opSpaceRe.ReplaceAllString(hyphenRe.ReplaceAllString(orBranch, " "), "$1")
		tokens = append(tokens, andRe.Split(strings.TrimSpace(rest), -1)...)
	}

	allowed, flagged := stabilityStable, false
	for _, token := range tokens {
		for _, m := range flagRe.FindAllStringSubmatch(token, -1) {
			allowed, flagged = min(allowed, flagStabilities[strings.ToLower(m[1])]), true
		}
	}
	if flagged {
		return allowed
	}

	for _, token := range tokens {
		if token != "" && !strings.ContainsAny(token, " \t@") {
			allowed = min(allowed, tokenStability(token))
		}
	}
	return allowed
}

// tokenStability returns the stability of the version in a single constraint (e.g. ^1.2-beta1 is beta).
// patch releases (e.g. 1.2.3-p1) are stable
func tokenStability(token string) int {
	t := strings.ToLower(token)
	if strings.HasPrefix(t, "dev-") || strings.HasSuffix(t, "dev") {
		return stabilityDev
	}
	v, _, err := parseDigits(strings.TrimLeft(t, "^~<>=!"))
	if err != nil || v.stability > stabilityStable {
		return stabilityStable
	}
	return v.stability
}

// getMinimumVersionForGroup finds the smallest version satisfying an AND-group of comparators, if any.
// without a lower bound the minimum is 0.0.0, the lowest stable release.
// floor is the least stable release that is installable
func getMinimumVersionForGroup(group []comparator, floor int) (version, bool) {
	var lower version
	hasLower := false
	for _, p := range group {
		var candidate version
		switch p.op {
		case ">=", "==":
			candidate = p.v
		case ">":
			candidate = p.v.next()
		default:
			continue
		}
		if !hasLower || candidate.cmp(lower) > 0 {
			lower, hasLower = candidate, true
		}
	}
	// raise the lower bound to the lowest installable release
	// (e.g. >=1.2.0.0-dev is 1.2.0 when stable is required, 1.2.0-beta when beta is allowed)
	if lower.stability < floor {
		lower.stability, lower.num = floor, 0
	}
	// A != carving out the bound itself bumps it to the next discrete version;
	// any other failing comparator is an upper bound below the lower: empty branch.
	for retry := true; retry; {
		retry = false
		for _, p := range group {
			if lower.holds(p) {
				continue
			}
			if p.op != "!=" {
				return version{}, false
			}
			lower = lower.next()
			retry = true
			break
		}
	}
	return lower, true
}

// getMinimumVersion finds the smallest satisfiable version across OR branches.
func getMinimumVersion(dnf [][]comparator, floor int) (version, bool) {
	var best version
	found := false
	for _, group := range dnf {
		if v, ok := getMinimumVersionForGroup(group, floor); ok && (!found || v.cmp(best) < 0) {
			best, found = v, true
		}
	}
	return best, found
}

func getMinimumVersionForConstraint(constraint string) (string, error) {
	dnf, err := parseConstraints(constraint)
	if err != nil {
		return "", err
	}

	// dev releases are branches, not tags, so the lowest installable release with dev allowed is an alpha
	floor := max(allowedStability(constraint), stabilityAlpha)

	minimum, ok := getMinimumVersion(dnf, floor)
	if !ok {
		return "", fmt.Errorf("unsatisfiable constraint: %s", constraint)
	}

	return minimum.String(), nil
}
