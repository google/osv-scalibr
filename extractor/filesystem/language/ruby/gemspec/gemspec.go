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

// Package gemspec extracts *.gemspec files.
package gemspec

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "ruby/gemspec"
)

// Regex expressions used for extracting gemspec package name and version.
var (
	reSpec            = regexp.MustCompile(`^Gem::Specification\.new`)
	reName            = regexp.MustCompile(`\s*\w+\.name\s*=\s*["']([^"']+)["']`)
	reVerLiteral      = regexp.MustCompile(`\s*\w+\.version\s*=\s*["']([^"']+)["']`)
	reVerConst        = regexp.MustCompile(`\s*\w+\.version\s*=\s*([A-Za-z0-9_:]+)`)
	reRequireRel      = regexp.MustCompile(`^\s*require_relative\s+["']([^"']+)["']`)
	reRequireLiteral  = regexp.MustCompile(`^\s*require\s+["']([^"']+)["']`)
	reConstAssignment = regexp.MustCompile(`\b([A-Z][A-Za-z0-9_]*)\s*=\s*(?:'([^']+)'|"([^"]+)")(?:\s*\.freeze)?`)
)

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the extractor.
func DefaultConfig() Config {
	return Config{
		Stats:            nil,
		MaxFileSizeBytes: 0,
	}
}

// Extractor extracts RubyGem package info from *.gemspec files.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Ruby gemspec extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{
		stats:            cfg.Stats,
		maxFileSizeBytes: cfg.MaxFileSizeBytes,
	}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired return true if the specified file matched the .gemspec file
// pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Ext(path) != ".gemspec" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.stats == nil {
		return
	}
	e.stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts packages from the .gemspec file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	p, err := extract(input.Path, input.FS, input.Reader)
	e.reportFileExtracted(input.Path, input.Info, filesystem.ExtractorErrorToFileExtractedResult(err))
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("gemspec.parse: %w", err)
	}
	if p == nil {
		return inventory.Inventory{}, nil
	}

	p.Locations = []string{input.Path}
	return inventory.Inventory{Packages: []*extractor.Package{p}}, nil
}

func (e Extractor) reportFileExtracted(path string, fileinfo fs.FileInfo, result stats.FileExtractedResult) {
	if e.stats == nil {
		return
	}
	var fileSizeBytes int64
	if fileinfo != nil {
		fileSizeBytes = fileinfo.Size()
	}
	e.stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// extract searches for the required name and version lines in the gemspec
// file using regex. It handles version strings defined either inline or via a
// constant populated through require_relative.
// Based on: https://guides.rubygems.org/specification-reference/
func extract(path string, fsys fs.FS, r io.Reader) (*extractor.Package, error) {
	buf := bufio.NewScanner(r)
	gemName, gemVer := "", ""
	foundStart := false
	var (
		requirePaths    []string
		versionConst    string
		inlineConstants = make(map[string]string)
	)
	reqAccum := &requireAccumulator{}

	for buf.Scan() {
		line := buf.Text()

		requirePaths = appendUnique(requirePaths, reqAccum.Add(line)...)

		if matches := reConstAssignment.FindStringSubmatch(line); len(matches) > 1 {
			if val := constantValueFromMatch(matches); val != "" {
				inlineConstants[matches[1]] = val
			}
		}

		if !foundStart {
			start := reSpec.FindString(line)
			if start != "" {
				foundStart = true
			}
			continue
		}
		if gemName != "" && gemVer != "" {
			break
		}
		if gemName == "" {
			nameArr := reName.FindStringSubmatch(line)
			if len(nameArr) > 1 {
				gemName = nameArr[1]
				continue
			}
		}
		if gemVer == "" {
			if verArr := reVerLiteral.FindStringSubmatch(line); len(verArr) > 1 {
				gemVer = verArr[1]
				continue
			}
			if versionConst == "" {
				if constMatch := reVerConst.FindStringSubmatch(line); len(constMatch) > 1 {
					versionConst = constMatch[1]
				}
			}
		}
	}

	if err := buf.Err(); err != nil {
		log.Warnf("error scanning gemspec file %s: %v", path, err)
	}
	requirePaths = appendUnique(requirePaths, reqAccum.Flush()...)

	// This was likely a marshalled gemspec. Not a readable text file.
	if !foundStart {
		log.Warnf("error scanning gemspec (%s) could not find start of spec definition", path)
		return nil, nil
	}

	if gemVer == "" && versionConst != "" {
		if constName, ok := versionConstantName(versionConst); ok {
			if v, ok := inlineConstants[constName]; ok {
				gemVer = v
			} else if resolved, err := resolveVersionFromRequires(fsys, path, requirePaths, constName); err == nil {
				gemVer = resolved
			} else {
				log.Debugf("unable to resolve version constant %q in gemspec %s: %v", versionConst, path, err)
			}
		}
	}

	if gemName == "" || gemVer == "" {
		return nil, fmt.Errorf("failed to parse gemspec name (%v) and version (%v)", gemName, gemVer)
	}

	return &extractor.Package{
		Name:     gemName,
		Version:  gemVer,
		PURLType: purl.TypeGem,
	}, nil
}

func resolveVersionFromRequires(fsys fs.FS, gemspecPath string, requirePaths []string, constName string) (string, error) {
	if fsys == nil {
		return "", fmt.Errorf("filesystem unavailable for resolving version constant")
	}

	gemspecDir := filepath.Dir(gemspecPath)
	visited := make(map[string]struct{})

	for _, req := range requirePaths {
		if req == "" {
			continue
		}

		candidates := versionFileCandidates(req)
		for _, candidate := range candidates {
			fullPath := candidate
			if gemspecDir != "." && gemspecDir != "" {
				fullPath = filepath.Join(gemspecDir, candidate)
			}
			fullPath = filepath.Clean(fullPath)
			if _, ok := visited[fullPath]; ok {
				continue
			}
			visited[fullPath] = struct{}{}

			version, err := findConstantValueInFile(fsys, fullPath, constName)
			if err == nil {
				return version, nil
			}
		}
	}

	return "", fmt.Errorf("unable to resolve constant %s from require_relative targets", constName)
}

func versionConstantName(expr string) (string, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", false
	}
	parts := strings.Split(expr, "::")
	name := parts[len(parts)-1]
	// Support common version constant naming patterns
	upperName := strings.ToUpper(name)
	if upperName == "VERSION" {
		return name, true
	}
	return "", false
}

func versionFileCandidates(req string) []string {
	req = strings.TrimSpace(req)
	req = strings.TrimPrefix(req, "./")
	req = filepath.Clean(req)
	if filepath.Ext(req) == ".rb" {
		return []string{req}
	}
	return []string{req, req + ".rb"}
}

func constantValueFromMatch(matches []string) string {
	if len(matches) > 2 && matches[2] != "" {
		return matches[2]
	}
	if len(matches) > 3 && matches[3] != "" {
		return matches[3]
	}
	return ""
}

func findConstantValueInFile(fsys fs.FS, path, constName string) (string, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if matches := reConstAssignment.FindStringSubmatch(line); len(matches) > 1 && matches[1] == constName {
			if val := constantValueFromMatch(matches); val != "" {
				return val, nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("constant %s not found in %s", constName, path)
}

// extractRequireTargets returns project-relative paths referenced by require or
// require_relative statements on the provided line of Ruby code.
func extractRequireTargets(line string) []string {
	stripped := stripInlineComment(line)
	if stripped == "" {
		return nil
	}

	trimmed := strings.TrimSpace(stripped)
	keyword := requireKeyword(trimmed)
	if keyword == "" {
		return nil
	}

	var results []string

	if keyword == "require_relative" {
		// Fast path: direct require_relative "literal"
		if matches := reRequireRel.FindStringSubmatch(trimmed); len(matches) > 1 {
			results = appendUnique(results, matches[1])
		}
	} else {
		// For plain require, only include likely project-local files.
		if matches := reRequireLiteral.FindStringSubmatch(trimmed); len(matches) > 1 && looksLikeProjectPath(matches[1]) {
			results = appendUnique(results, matches[1])
		}
	}

	// Parse expressions following the keyword, e.g. File.join(...)
	expr := strings.TrimSpace(trimmed[len(keyword):])
	if expr == "" {
		return results
	}

	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		expr = strings.TrimSpace(expr[1 : len(expr)-1])
	}
	// Require statements often have trailing conditionals; drop them.
	expr = strings.TrimSpace(trimRubyTrailingCondition(expr))
	if expr == "" {
		return results
	}

	if val, ok := parseQuotedLiteral(expr); ok {
		if keyword == "require_relative" || looksLikeProjectPath(val) {
			results = appendUnique(results, val)
		}
	}

	if strings.HasPrefix(expr, "File.join") {
		// Handle require_relative File.join('lib', 'foo') patterns.
		if path := parseFileJoin(expr); path != "" {
			results = appendUnique(results, path)
		}
	}
	if strings.HasPrefix(expr, "File.expand_path") {
		// Support File.expand_path('lib/foo', __dir__)
		if path := parseFileExpand(expr); path != "" {
			results = appendUnique(results, path)
		}
	}
	if strings.Contains(expr, "File.dirname(__FILE__)") || strings.Contains(expr, "__dir__") {
		// Handle legacy File.dirname(__FILE__) + '/lib/foo'
		if path := parseDirnameConcat(expr); path != "" {
			results = appendUnique(results, path)
		}
	}
	// TODO: add support for additional static helpers (e.g. File.dirname(__FILE__) << '/lib', %w literals)

	return results
}

// requireAccumulator builds a complete require/require_relative statement that
// may span multiple lines and yields extracted targets once the statement is
// syntactically complete.
type requireAccumulator struct {
	pending string
}

func (a *requireAccumulator) Add(line string) []string {
	stripped := stripInlineComment(line)
	if stripped == "" {
		return nil
	}

	if a.pending != "" {
		// Concatenate continued lines; space ensures tokens stay separated.
		a.pending = strings.TrimSpace(a.pending + " " + stripped)
		if requireStatementComplete(a.pending) {
			statement := a.pending
			a.pending = ""
			return extractRequireTargets(statement)
		}
		return nil
	}

	if keyword := requireKeyword(stripped); keyword != "" {
		// Start buffering a new require statement.
		a.pending = stripped
		if requireStatementComplete(a.pending) {
			statement := a.pending
			a.pending = ""
			return extractRequireTargets(statement)
		}
		return nil
	}

	// If no require keyword and no pending context, attempt standalone extraction.
	return extractRequireTargets(stripped)
}

func (a *requireAccumulator) Flush() []string {
	if a.pending == "" {
		return nil
	}
	if !requireStatementComplete(a.pending) {
		return nil
	}
	statement := a.pending
	a.pending = ""
	return extractRequireTargets(statement)
}

// appendUnique appends candidates that are non-empty and not already present in existing.
func appendUnique(existing []string, candidates ...string) []string {
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		duplicate := false
		for _, current := range existing {
			if current == candidate {
				duplicate = true
				break
			}
		}
		if !duplicate {
			existing = append(existing, candidate)
		}
	}
	return existing
}

// parseFileJoin attempts to extract a static path from File.join calls with
// literal string arguments; it returns an empty string if parsing fails.
func parseFileJoin(expr string) string {
	args, ok := extractCallArguments(expr, "File.join")
	if !ok {
		return ""
	}

	segments := splitArgs(args)
	var parts []string
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if val, ok := parseQuotedLiteral(segment); ok {
			// Only literal segments contribute to a static path.
			parts = append(parts, val)
			continue
		}
		// Any non-literal segment prevents static resolution.
		return ""
	}
	if len(parts) == 0 {
		return ""
	}

	joined := filepath.Join(parts...)
	return filepath.Clean(joined)
}

// parseFileExpand extracts the first argument to File.expand_path when it is a
// literal or another supported static helper, returning an empty string otherwise.
func parseFileExpand(expr string) string {
	args, ok := extractCallArguments(expr, "File.expand_path")
	if !ok {
		return ""
	}
	segments := splitArgs(args)
	if len(segments) == 0 {
		return ""
	}
	first := strings.TrimSpace(segments[0])
	// File.expand_path may wrap File.join or a literal path.
	if strings.HasPrefix(first, "File.join") {
		return parseFileJoin(first)
	}
	if val, ok := parseQuotedLiteral(first); ok {
		return filepath.Clean(val)
	}
	return ""
}

// parseDirnameConcat resolves concatenations that include File.dirname(__FILE__)
// or __dir__ with static path literals to produce a relative path.
func parseDirnameConcat(expr string) string {
	parts := splitOnPlus(expr)
	if len(parts) == 0 {
		return ""
	}
	hasDirname := false
	var literals []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "File.dirname(__FILE__)") || part == "__dir__" {
			// Track presence of dirname anchor; no literal to append yet.
			hasDirname = true
			continue
		}
		if strings.HasSuffix(part, "__dir__") && strings.Contains(part, "File.expand_path") {
			// handled elsewhere; skip to avoid double detection.
			continue
		}
		if strings.HasPrefix(part, "File.join") {
			// Support nested File.join helpers within concatenations.
			if joined := parseFileJoin(part); joined != "" {
				literals = append(literals, joined)
			}
			continue
		}
		if strings.HasPrefix(part, "File.expand_path") {
			// Allow nested expand_path inside concatenations.
			if val := parseFileExpand(part); val != "" {
				literals = append(literals, val)
			}
			continue
		}
		if val, ok := parseQuotedLiteral(part); ok {
			literals = append(literals, val)
		}
	}
	if !hasDirname || len(literals) == 0 {
		return ""
	}
	for i, lit := range literals {
		literals[i] = strings.TrimPrefix(lit, string(filepath.Separator))
	}
	joined := filepath.Clean(filepath.Join(literals...))
	return strings.TrimPrefix(joined, string(filepath.Separator))
}

// extractCallArguments returns the argument string inside the parentheses for
// the specified call prefix, handling nested parentheses and quoted strings.
func extractCallArguments(expr, prefix string) (string, bool) {
	rem := strings.TrimSpace(expr)
	if !strings.HasPrefix(rem, prefix) {
		return "", false
	}
	rem = strings.TrimSpace(rem[len(prefix):])
	if !strings.HasPrefix(rem, "(") {
		return "", false
	}
	rem = rem[1:]
	depth := 1
	var b strings.Builder
	inSingle, inDouble := false, false
	for i := 0; i < len(rem); i++ {
		ch := rem[i]
		switch ch {
		case '\\':
			if inSingle || inDouble {
				if i+1 < len(rem) {
					b.WriteByte(ch)
					i++
					b.WriteByte(rem[i])
					continue
				}
			}
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '(':
			if !inSingle && !inDouble {
				depth++
			}
		case ')':
			if !inSingle && !inDouble {
				depth--
				if depth == 0 {
					// Return captured arguments once parentheses balance.
					return strings.TrimSpace(b.String()), true
				}
			}
		}
		if depth > 0 {
			b.WriteByte(ch)
		}
	}
	return "", false
}

// splitArgs splits a comma-separated argument list into individual arguments,
// respecting quoted strings and nested parentheses.
func splitArgs(expr string) []string {
	var (
		args       []string
		current    strings.Builder
		inSingle   bool
		inDouble   bool
		parenDepth int
	)

	for i := 0; i < len(expr); i++ {
		ch := expr[i]
		switch ch {
		case '\\':
			if inSingle || inDouble {
				current.WriteByte(ch)
				if i+1 < len(expr) {
					i++
					current.WriteByte(expr[i])
				}
				continue
			}
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '(':
			if !inSingle && !inDouble {
				parenDepth++
			}
		case ')':
			if !inSingle && !inDouble && parenDepth > 0 {
				parenDepth--
			}
		case ',':
			if !inSingle && !inDouble && parenDepth == 0 {
				// Emit current argument when outside nested constructs.
				args = append(args, strings.TrimSpace(current.String()))
				current.Reset()
				continue
			}
		}
		current.WriteByte(ch)
	}

	if tail := strings.TrimSpace(current.String()); tail != "" {
		args = append(args, tail)
	}
	return args
}

// parseQuotedLiteral returns the unescaped contents of a quoted Ruby literal and
// a boolean indicating success.
func parseQuotedLiteral(expr string) (string, bool) {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return "", false
	}
	quote := trimmed[0]
	if quote != '\'' && quote != '"' {
		return "", false
	}
	var (
		value   strings.Builder
		escaped bool
	)
	for i := 1; i < len(trimmed); i++ {
		ch := trimmed[i]
		if escaped {
			value.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == quote {
			// Found closing quote; return accumulated value.
			return value.String(), true
		}
		value.WriteByte(ch)
	}
	return "", false
}

// stripInlineComment removes Ruby inline comments while preserving quoted hash
// characters inside string literals.
func stripInlineComment(line string) string {
	var (
		inSingle bool
		inDouble bool
		escaped  bool
	)
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if escaped {
			escaped = false
			continue
		}
		switch ch {
		case '\\':
			if inSingle || inDouble {
				escaped = true
			}
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				// Trim comment marker and trailing spaces.
				return strings.TrimSpace(line[:i])
			}
		}
	}
	return strings.TrimSpace(line)
}

// trimRubyTrailingCondition removes trailing single-line conditionals (if,
// unless, while, until) to simplify require target parsing.
func trimRubyTrailingCondition(expr string) string {
	for _, kw := range []string{" if ", " unless ", " while ", " until "} {
		if idx := strings.Index(expr, kw); idx >= 0 {
			return strings.TrimSpace(expr[:idx])
		}
	}
	return expr
}

// requireKeyword returns the require variant found at the beginning of expr, or
// an empty string if none is present.
func requireKeyword(expr string) string {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "require_relative") {
		return "require_relative"
	}
	if strings.HasPrefix(trimmed, "require(") || strings.HasPrefix(trimmed, "require ") {
		return "require"
	}
	return ""
}

// looksLikeProjectPath heuristically determines whether the provided path refers
// to a project-local file rather than a standard library or gem.
func looksLikeProjectPath(path string) bool {
	if path == "" {
		return false
	}
	if strings.HasPrefix(path, ".") {
		return true
	}
	if strings.Contains(path, "/") {
		return true
	}
	if strings.HasSuffix(path, ".rb") {
		return true
	}
	return false
}

// requireStatementComplete reports whether the given require statement has
// balanced delimiters and closed quotes, indicating it is ready to be parsed.
func requireStatementComplete(expr string) bool {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return false
	}
	trimmed = strings.TrimSpace(trimRubyTrailingCondition(trimmed))
	inSingle := false
	inDouble := false
	escaped := false
	depth := 0
	for i := 0; i < len(trimmed); i++ {
		ch := trimmed[i]
		if escaped {
			escaped = false
			continue
		}
		switch ch {
		case '\\':
			if inSingle || inDouble {
				escaped = true
			}
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '(':
			if !inSingle && !inDouble {
				depth++
			}
		case ')':
			if !inSingle && !inDouble {
				depth--
			}
		}
	}
	return !inSingle && !inDouble && depth <= 0
}

// splitOnPlus splits an expression on plus operators while respecting quoted
// strings and balanced parentheses, returning trimmed segments.
func splitOnPlus(expr string) []string {
	var (
		parts      []string
		current    strings.Builder
		inSingle   bool
		inDouble   bool
		parenDepth int
	)
	for i := 0; i < len(expr); i++ {
		ch := expr[i]
		switch ch {
		case '\\':
			if inSingle || inDouble {
				current.WriteByte(ch)
				if i+1 < len(expr) {
					i++
					current.WriteByte(expr[i])
				}
				continue
			}
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '(':
			if !inSingle && !inDouble {
				parenDepth++
			}
		case ')':
			if !inSingle && !inDouble && parenDepth > 0 {
				parenDepth--
			}
		case '+':
			if !inSingle && !inDouble && parenDepth == 0 {
				parts = append(parts, strings.TrimSpace(current.String()))
				current.Reset()
				continue
			}
		}
		current.WriteByte(ch)
	}
	if tail := strings.TrimSpace(current.String()); tail != "" {
		parts = append(parts, tail)
	}
	return parts
}
