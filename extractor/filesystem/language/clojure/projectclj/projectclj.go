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

// Package projectclj extracts Maven dependencies declared in Leiningen
// project.clj files.
package projectclj

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "clojure/projectclj"

	// defaultMaxFileSizeBytes is the maximum file size this extractor will process.
	defaultMaxFileSizeBytes = 10 * units.MiB // 10 MB

	// maxNestingDepth bounds how deeply forms may nest. Real project.clj files
	// nest a handful of levels; the bound keeps a hostile file from exhausting
	// the stack.
	maxNestingDepth = 256
)

// defaultProfiles are the profiles Leiningen applies without being asked:
// :default expands to [:base :system :user :provided :dev], and :test is
// added when running tests. Other profiles, such as version matrices like
// :1.10 or tooling like :benchmark, are only active under an explicit
// `lein with-profile`, and `lein pom` leaves them out too, so their
// dependencies are not reported.
var defaultProfiles = map[string]bool{
	"base":     true,
	"system":   true,
	"user":     true,
	"provided": true,
	"dev":      true,
	"test":     true,
	"default":  true,
}

// A project.clj is Clojure code whose interesting part is a single
// defproject form:
//
//	(def jackson-version "2.15.2")
//
//	(defproject my-app "0.1.0"
//	  :dependencies [[org.clojure/clojure "1.11.1"]
//	                 [cheshire "5.13.0"]
//	                 [com.fasterxml.jackson.core/jackson-databind ~jackson-version]
//	                 [ring/ring-core "1.12.2" :exclusions [commons-io]]]
//	  :managed-dependencies [[org.slf4j/slf4j-api "2.0.13"]]
//	  :profiles {:dev {:dependencies [[org.clojure/test.check "1.1.1"]]}})
//
// Each dependency is a vector [coordinate version & options]. A coordinate is
// either group/artifact or a bare symbol, in which case the group equals the
// artifact. The version may be omitted when :managed-dependencies supplies it,
// and may be an unquoted reference (~sym) to a string defined with a top-level
// def. Everything is reported against the Maven ecosystem, since every
// Leiningen coordinate is a Maven groupId:artifactId.
//
// :plugins are deliberately not reported: they are Leiningen build plugins
// that run in the build tool, not dependencies of the project. Dependencies
// of opt-in profiles are not reported either; see defaultProfiles.

// Extractor extracts Maven packages from Leiningen project.clj files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a project.clj extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	return &Extractor{maxFileSizeBytes: maxFileSizeBytes}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file is a project.clj file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "project.clj" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil || (e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes) {
		e.reportFileRequired(path, stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, result stats.FileRequiredResult) {
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:   path,
		Result: result,
	})
}

// Extract parses the project.clj file to extract its Maven dependencies.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	inv, err := e.extract(ctx, input)
	if e.Stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inv, err
}

func (e Extractor) extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	r := &reader{in: bufio.NewReader(input.Reader), line: 1}
	defs := map[string]string{}

	// Top-level forms are read one at a time. String defs seen before the
	// defproject form are remembered so ~sym versions can be resolved; the
	// rest of the file is not needed once defproject has been read.
	for {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, err
		}
		f, err := r.read(0)
		if errors.Is(err, io.EOF) {
			// No defproject: not a Leiningen project file.
			return inventory.Inventory{Packages: []*extractor.Package{}}, nil
		}
		if err != nil {
			return inventory.Inventory{}, fmt.Errorf("failed to parse %q: %w", input.Path, err)
		}
		if f.kind != kindList || len(f.children) == 0 || f.children[0].kind != kindSymbol {
			continue
		}
		switch f.children[0].text {
		case "def":
			if len(f.children) == 3 && f.children[1].kind == kindSymbol && f.children[2].kind == kindString {
				defs[f.children[1].text] = f.children[2].text
			}
		case "defproject":
			return inventory.Inventory{Packages: packagesFromProject(f, defs, input.Path)}, nil
		}
	}
}

// packagesFromProject collects the dependencies of a defproject form.
func packagesFromProject(project *form, defs map[string]string, path string) []*extractor.Package {
	// (defproject name version :key value :key value ...)
	opts := keywordPairs(project.children, 3)

	managed := map[string]string{}
	for _, dep := range vectorElems(opts[":managed-dependencies"]) {
		if d, ok := parseDependency(dep, defs, nil); ok && d.version != "" {
			managed[d.group+":"+d.artifact] = d.version
		}
	}

	c := &collector{packages: []*extractor.Package{}, seen: map[string]bool{}, path: path}
	for _, dep := range vectorElems(opts[":dependencies"]) {
		c.add(dep, defs, managed, "")
	}

	// :profiles {:dev {:dependencies [...]}, :provided [:base {:dependencies [...]}]}
	// A profile is either a map or a composite vector of maps and the names of
	// other profiles; only the maps declare dependencies.
	if profiles := opts[":profiles"]; profiles != nil && profiles.kind == kindMap {
		for i := 0; i+1 < len(profiles.children); i += 2 {
			key, val := profiles.children[i], profiles.children[i+1]
			if key.kind != kindKeyword {
				continue
			}
			group := strings.TrimPrefix(key.text, ":")
			if !defaultProfiles[group] {
				continue
			}
			var maps []*form
			switch val.kind {
			case kindMap:
				maps = []*form{val}
			case kindVector:
				for _, el := range val.children {
					if el.kind == kindMap {
						maps = append(maps, el)
					}
				}
			}
			for _, m := range maps {
				for _, dep := range vectorElems(keywordPairs(m.children, 0)[":dependencies"]) {
					c.add(dep, defs, managed, group)
				}
			}
		}
	}

	return c.packages
}

type collector struct {
	packages []*extractor.Package
	seen     map[string]bool
	path     string
}

// add reports one dependency vector. profile is empty for the top-level
// :dependencies and the profile name otherwise.
func (c *collector) add(dep *form, defs, managed map[string]string, profile string) {
	d, ok := parseDependency(dep, defs, managed)
	if !ok || d.version == "" {
		// Without a version there is nothing to match against advisories.
		return
	}

	var groups []string
	if profile != "" {
		groups = append(groups, profile)
	}
	if d.scope != "" && d.scope != "compile" && d.scope != profile {
		groups = append(groups, d.scope)
	}

	name := d.group + ":" + d.artifact
	key := strings.Join(append([]string{name, d.version, d.classifier}, groups...), "\x00")
	if c.seen[key] {
		return
	}
	c.seen[key] = true

	c.packages = append(c.packages, &extractor.Package{
		Name:     name,
		Version:  d.version,
		PURLType: purl.TypeMaven,
		Metadata: &javalockfile.Metadata{
			ArtifactID:   d.artifact,
			GroupID:      d.group,
			Type:         d.extension,
			Classifier:   d.classifier,
			DepGroupVals: groups,
		},
		Location: extractor.LocationFromPathAndLine(c.path, dep.line),
	})
}

type dependency struct {
	group, artifact, version string
	classifier, extension    string
	scope                    string
}

// parseDependency reads [coordinate version & options]. The version is
// optional; when it is missing it is looked up in managed, which may be nil.
func parseDependency(dep *form, defs, managed map[string]string) (dependency, bool) {
	if dep == nil || dep.kind != kindVector || len(dep.children) == 0 {
		return dependency{}, false
	}
	coord := dep.children[0]
	if coord.kind != kindSymbol && coord.kind != kindString {
		return dependency{}, false
	}

	var d dependency
	d.group, d.artifact, _ = strings.Cut(coord.text, "/")
	if d.artifact == "" {
		// A bare symbol names an artifact whose group is the same name.
		d.artifact = d.group
	}
	if d.group == "" || d.artifact == "" {
		return dependency{}, false
	}

	optStart := 1
	if len(dep.children) > 1 {
		switch v := dep.children[1]; v.kind {
		case kindString:
			d.version = v.text
			optStart = 2
		case kindUnquote:
			if len(v.children) == 1 && v.children[0].kind == kindSymbol {
				d.version = defs[v.children[0].text]
			}
			optStart = 2
		case kindKeyword:
			// No version; options start right away.
		default:
			optStart = 2
		}
	}
	if d.version == "" && managed != nil {
		d.version = managed[d.group+":"+d.artifact]
	}

	opts := keywordPairs(dep.children, optStart)
	d.classifier = stringValue(opts[":classifier"])
	d.extension = stringValue(opts[":extension"])
	d.scope = stringValue(opts[":scope"])
	return d, true
}

// keywordPairs reads :key value pairs from forms starting at index start.
// Elements that are not keywords in key position are skipped, so a stray
// form does not shift every pair after it.
func keywordPairs(forms []*form, start int) map[string]*form {
	pairs := map[string]*form{}
	for i := start; i < len(forms); i++ {
		if forms[i].kind != kindKeyword || i+1 >= len(forms) {
			continue
		}
		pairs[forms[i].text] = forms[i+1]
		i++
	}
	return pairs
}

func vectorElems(f *form) []*form {
	if f == nil || f.kind != kindVector {
		return nil
	}
	return f.children
}

func stringValue(f *form) string {
	if f == nil || (f.kind != kindString && f.kind != kindKeyword && f.kind != kindSymbol) {
		return ""
	}
	return strings.TrimPrefix(f.text, ":")
}

// ---------------------------------------------------------------------------
// A minimal streaming reader for the subset of Clojure syntax that appears in
// project.clj files. It only has to tell collections, symbols, keywords and
// strings apart; everything else is read and kept as an opaque form so that
// it never desynchronises the surrounding structure.

type formKind int

const (
	kindOther formKind = iota
	kindList
	kindVector
	kindMap
	kindSet
	kindSymbol
	kindKeyword
	kindString
	kindUnquote // ~form or ~@form
)

type form struct {
	kind     formKind
	text     string
	children []*form
	line     int
}

// closeError is returned by read when it meets a closing delimiter instead of
// a form. The collection reader uses it to find the end of its elements.
type closeError struct{ delim rune }

func (e closeError) Error() string {
	return fmt.Sprintf("unexpected closing delimiter %q", e.delim)
}

type reader struct {
	in   *bufio.Reader
	line int
}

func (r *reader) next() (rune, error) {
	c, _, err := r.in.ReadRune()
	if err == nil && c == '\n' {
		r.line++
	}
	return c, err
}

func (r *reader) unread(c rune) {
	_ = r.in.UnreadRune()
	if c == '\n' {
		r.line--
	}
}

func isWhitespace(c rune) bool { return unicode.IsSpace(c) || c == ',' }

func isDelimiter(c rune) bool {
	return isWhitespace(c) || strings.ContainsRune(`()[]{}";`, c)
}

// skipBlank consumes whitespace and line comments.
func (r *reader) skipBlank() error {
	for {
		c, err := r.next()
		if err != nil {
			return err
		}
		if c == ';' {
			for c != '\n' {
				if c, err = r.next(); err != nil {
					return err
				}
			}
			continue
		}
		if !isWhitespace(c) {
			r.unread(c)
			return nil
		}
	}
}

// read returns the next form. It returns io.EOF when the input ends between
// forms and a closeError when it meets a closing delimiter.
func (r *reader) read(depth int) (*form, error) {
	if depth > maxNestingDepth {
		return nil, fmt.Errorf("line %d: forms nested deeper than %d", r.line, maxNestingDepth)
	}
	if err := r.skipBlank(); err != nil {
		return nil, err
	}
	line := r.line
	c, err := r.next()
	if err != nil {
		return nil, err
	}

	switch c {
	case '(':
		return r.readColl(kindList, ')', line, depth)
	case '[':
		return r.readColl(kindVector, ']', line, depth)
	case '{':
		return r.readColl(kindMap, '}', line, depth)
	case ')', ']', '}':
		return nil, closeError{delim: c}
	case '"':
		s, err := r.readString()
		if err != nil {
			return nil, err
		}
		return &form{kind: kindString, text: s, line: line}, nil
	case '\'', '`', '@':
		// Quote, syntax quote and deref do not change what is being declared.
		return r.readOperand(depth)
	case '~':
		next, err := r.next()
		if err != nil {
			return nil, unexpectedEOF(err)
		}
		if next != '@' {
			r.unread(next)
		}
		inner, err := r.readOperand(depth)
		if err != nil {
			return nil, err
		}
		return &form{kind: kindUnquote, children: []*form{inner}, line: line}, nil
	case '^':
		// Metadata such as ^:replace: read and drop it, keep the form it annotates.
		if _, err := r.readOperand(depth); err != nil {
			return nil, err
		}
		return r.readOperand(depth)
	case '\\':
		// Character literal: \a, \newline, \] ...
		if _, err := r.next(); err != nil {
			return nil, unexpectedEOF(err)
		}
		if _, err := r.readToken(); err != nil {
			return nil, err
		}
		return &form{kind: kindOther, line: line}, nil
	case '#':
		return r.readDispatch(line, depth)
	}

	r.unread(c)
	tok, err := r.readToken()
	if err != nil {
		return nil, err
	}
	switch {
	case strings.HasPrefix(tok, ":"):
		return &form{kind: kindKeyword, text: tok, line: line}, nil
	case isNumber(tok):
		return &form{kind: kindOther, text: tok, line: line}, nil
	default:
		return &form{kind: kindSymbol, text: tok, line: line}, nil
	}
}

// readOperand reads the form a prefix such as ' or ^ applies to. Running
// out of input or meeting a closing delimiter there is malformed input.
func (r *reader) readOperand(depth int) (*form, error) {
	f, err := r.read(depth)
	if ce := (closeError{}); errors.As(err, &ce) {
		return nil, fmt.Errorf("line %d: missing form before %q", r.line, ce.delim)
	}
	if err != nil {
		return nil, unexpectedEOF(err)
	}
	return f, nil
}

func (r *reader) readColl(kind formKind, closing rune, line, depth int) (*form, error) {
	f := &form{kind: kind, line: line}
	for {
		el, err := r.read(depth + 1)
		if ce := (closeError{}); errors.As(err, &ce) {
			if ce.delim != closing {
				return nil, fmt.Errorf("line %d: expected %q, found %q", r.line, closing, ce.delim)
			}
			return f, nil
		}
		if err != nil {
			return nil, unexpectedEOF(err)
		}
		f.children = append(f.children, el)
	}
}

func (r *reader) readDispatch(line, depth int) (*form, error) {
	c, err := r.next()
	if err != nil {
		return nil, unexpectedEOF(err)
	}
	switch c {
	case '{':
		return r.readColl(kindSet, '}', line, depth)
	case '_':
		// #_ discards the next form entirely.
		if _, err := r.readOperand(depth); err != nil {
			return nil, err
		}
		return r.read(depth)
	case '"':
		// Regex literal.
		if _, err := r.readString(); err != nil {
			return nil, err
		}
		return &form{kind: kindOther, line: line}, nil
	case '(':
		// Anonymous function: read it but never treat it as data.
		f, err := r.readColl(kindList, ')', line, depth)
		if err != nil {
			return nil, err
		}
		f.kind = kindOther
		return f, nil
	case '?':
		// Reader conditional #?(...) or #?@(...): kept opaque.
		next, err := r.next()
		if err != nil {
			return nil, unexpectedEOF(err)
		}
		if next != '@' {
			r.unread(next)
		}
		f, err := r.readOperand(depth)
		if err != nil {
			return nil, err
		}
		return &form{kind: kindOther, children: f.children, line: line}, nil
	case '\'':
		// Var quote #'sym.
		return r.readOperand(depth)
	case '#':
		// Symbolic value such as ##Inf.
		if _, err := r.readToken(); err != nil {
			return nil, err
		}
		return &form{kind: kindOther, line: line}, nil
	case ':':
		// Namespaced map #:ns{...}: drop the prefix, keep the map.
		if _, err := r.readToken(); err != nil {
			return nil, err
		}
		return r.readOperand(depth)
	}
	// Tagged literal such as #inst "...": the tag, then the tagged form.
	r.unread(c)
	if _, err := r.readToken(); err != nil {
		return nil, err
	}
	if _, err := r.readOperand(depth); err != nil {
		return nil, err
	}
	return &form{kind: kindOther, line: line}, nil
}

func (r *reader) readString() (string, error) {
	var b strings.Builder
	for {
		c, err := r.next()
		if err != nil {
			return "", unexpectedEOF(err)
		}
		switch c {
		case '"':
			return b.String(), nil
		case '\\':
			esc, err := r.next()
			if err != nil {
				return "", unexpectedEOF(err)
			}
			switch esc {
			case 'n':
				b.WriteRune('\n')
			case 't':
				b.WriteRune('\t')
			default:
				b.WriteRune(esc)
			}
		default:
			b.WriteRune(c)
		}
	}
}

// readToken reads a symbol, keyword or number up to the next delimiter.
func (r *reader) readToken() (string, error) {
	var b strings.Builder
	for {
		c, err := r.next()
		if errors.Is(err, io.EOF) {
			return b.String(), nil
		}
		if err != nil {
			return "", err
		}
		if isDelimiter(c) {
			r.unread(c)
			return b.String(), nil
		}
		b.WriteRune(c)
	}
}

func isNumber(tok string) bool {
	t := strings.TrimLeft(tok, "+-")
	return t != "" && unicode.IsDigit(rune(t[0]))
}

func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
