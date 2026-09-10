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

// Package buildzigzon extracts build.zig.zon files from installed and depended Zig packages.
package buildzigzon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"text/scanner"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "zig/buildzigzon"

	// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSizeBytes = 30 * units.MiB
)

// Extractor extracts Zig package info from build.zig.zon files.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
	// Flag for determining mode, artifact or source code scanning
	scanDependencies bool
}

// NewWithDeps returns a Zig build.zig.zon source code extractor.
func NewWithDeps(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.ZigBuildZigZonConfig { return c.GetBuildzigzon() })
	if specific.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = specific.GetMaxFileSizeBytes()
	}

	return &Extractor{maxFileSizeBytes: maxFileSizeBytes, scanDependencies: true}, nil
}

// New returns a Zig build.zig.zon artifact extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.ZigBuildZigZonConfig { return c.GetBuildzigzon() })
	if specific.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = specific.GetMaxFileSizeBytes()
	}

	return &Extractor{maxFileSizeBytes: maxFileSizeBytes, scanDependencies: specific.GetScanDependencies()}, nil
}

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired return true if the specified file matched the build.zig.zon file name.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "build.zig.zon" {
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

// Extract extracts from build.zig.zon files
// It extract only name and version from the file if the mode is artifact, but if it is source code scanning mode, it will parse and extract dependencies field.
// Refer to example build.zig.zon file: https://github.com/ziglang/zig/blob/master/doc/build.zig.zon.md
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var pkgs []*extractor.Package
	var err error
	if e.scanDependencies {
		pkgs, err = e.parseDependenciesField(ctx, input)
	} else {
		pkgs, err = e.parseNameVersionInfo(ctx, input)
	}
	if e.stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inventory.Inventory{Packages: pkgs}, err
}

// parseFile parses the scanned file into its top-level ZON struct.
func (e Extractor) parseFile(ctx context.Context, input *filesystem.ScanInput) (*zonValue, error) {
	root, err := parseZON(input.Reader)
	if err == nil && root != nil {
		return root, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("%s halted due to context error: %w", e.Name(), ctxErr)
	}
	return nil, nil
}

// parseNameVersionInfo extracts the top-level .name and .version fields.
//
// Supports both the current and the legacy spelling of .name:
//
//	.name = .zigmodule,    (current: enum literal)
//	.name = "zigmodule",   (legacy: quoted string)
//	.version = "0.0.1",
func (e Extractor) parseNameVersionInfo(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Package, error) {
	root, err := e.parseFile(ctx, input)
	if err != nil {
		return nil, err
	}

	name := root.field("name").stringOrEnum()
	version := root.field("version").stringValue()
	if name == "" || version == "" {
		return []*extractor.Package{}, nil
	}

	return []*extractor.Package{{
		Name:     name,
		Version:  version,
		PURLType: purl.TypeZig,
		Location: extractor.LocationFromPath(input.Path),
	}}, nil
}

// parseDependenciesField extracts a package per entry of the .dependencies struct.
//
// Example format:
//
//	 .dependencies = .{
//	       .zigrc = .{
//	           .url = "git+https://github.com/Aandreba/zigrc/#b1e98f1cc506e975bdb27341c27d920021e7b4d8",
//	           .hash = "zigrc-1.0.0-lENlWzvQAACulrbkL9PVhWjFsWSkYhi7AmfSbCM-2Xlh",
//	       },
//	},
func (e Extractor) parseDependenciesField(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Package, error) {
	root, err := e.parseFile(ctx, input)
	if err != nil {
		return nil, err
	}

	packages := []*extractor.Package{}
	for _, entry := range root.field("dependencies").namedFields() {
		dep := parseHash(entry.value.field("hash").stringValue())
		if dep.Name == "" || dep.Version == "" {
			continue
		}
		packages = append(packages, &extractor.Package{
			Name:     dep.Name,
			Version:  dep.Version,
			PURLType: purl.TypeZig,
			Location: extractor.LocationFromPath(input.Path),
		})
	}
	return packages, nil
}

// Dependency holds a single dependency entry.
type Dependency struct {
	Name    string // extracted from .hash (empty if the hash carries no name)
	Version string // extracted from .hash, empty for legacy "1220..." or path deps
}

// sizedHashLen is the length of the digest at the end of a current-format .hash value.
const sizedHashLen = 44

// parseHash extracts a name and version from a dependency's .hash value.
//
// Formats:
//
//	Legacy:  "1220<hex>"                 -> no name or version
//	No-zon:  "N-V-<44 chars>"            -> placeholder for deps without a build.zig.zon
//	Current: "name-version-<44 chars>"   -> version may contain dashes, e.g. "0.5.0-dev"
func parseHash(hash string) Dependency {
	// Legacy multihash format, and anything too short to hold a name and a version.
	if strings.HasPrefix(hash, "1220") || len(hash) <= sizedHashLen+1 {
		return Dependency{}
	}
	// The digest is always the trailing 44 characters, preceded by a dash.
	cutpoint := len(hash) - sizedHashLen
	if hash[cutpoint-1] != '-' {
		return Dependency{}
	}
	// Zig identifiers can't contain dashes, so the first dash separates the name from
	// the version. See https://github.com/ziglang/zig/issues/20178.
	name, version, found := strings.Cut(hash[:cutpoint-1], "-")
	if !found {
		return Dependency{}
	}
	// Placeholder used for packages that don't ship a build.zig.zon.
	if name == "N" && version == "V" {
		return Dependency{}
	}
	return Dependency{Name: name, Version: version}
}

// zonKind describes the type of a parsed ZON value.
type zonKind int

const (
	// kindOther is any value the extractor doesn't need to inspect: numbers, bools, chars.
	kindOther zonKind = iota
	// kindString is a string literal, e.g. "1.0.0".
	kindString
	// kindEnum is an enum literal, e.g. .hello_world.
	kindEnum
	// kindBlock is a .{ ... } struct or tuple literal.
	kindBlock
)

// zonField is a single named field of a .{ ... } block.
type zonField struct {
	key   string
	value *zonValue
}

// zonValue is a parsed ZON value.
type zonValue struct {
	kind zonKind
	// text holds the contents of a string literal or the name of an enum literal.
	text string
	// fields holds the named fields of a block, in file order.
	fields []zonField
	// items holds the unnamed elements of a block, in file order.
	items []*zonValue
}

// field returns the value of the named field, or nil if the value is absent, isn't a
// block, or has no such field.
func (v *zonValue) field(name string) *zonValue {
	if v == nil {
		return nil
	}
	for _, f := range v.fields {
		if f.key == name {
			return f.value
		}
	}
	return nil
}

// namedFields returns the named fields of a block in file order, or nil if the value
// is absent or isn't a block.
func (v *zonValue) namedFields() []zonField {
	if v == nil {
		return nil
	}
	return v.fields
}

// stringValue returns the contents of a string literal, or "" for any other value.
func (v *zonValue) stringValue() string {
	if v == nil || v.kind != kindString {
		return ""
	}
	return v.text
}

// stringOrEnum returns the contents of a string or enum literal, so that both
// .name = "foo" and .name = .foo yield "foo".
func (v *zonValue) stringOrEnum() string {
	if v == nil || (v.kind != kindString && v.kind != kindEnum) {
		return ""
	}
	return v.text
}

const (
	// maxDepth bounds recursion so deeply nested or malformed input can't exhaust the stack.
	maxDepth = 64
)

// parser is a recursive descent parser for ZON, the Zig object notation used by
// build.zig.zon. It tokenizes with text/scanner so that comments, string literals and
// nesting are handled by the lexer rather than by regexes and hand-rolled brace
// counting, both of which trip over braces, quotes and "//" inside string values.
type parser struct {
	scanner scanner.Scanner
	// tok and text are the current token and its source text.
	tok  rune
	text string
	// tokens counts the tokens consumed so far, used to guarantee forward progress.
	tokens int
	depth  int
	err    error
}

func newParser(r io.Reader) *parser {
	p := &parser{}
	p.scanner.Init(r)
	p.scanner.Mode = scanner.ScanIdents | scanner.ScanFloats | scanner.ScanChars |
		scanner.ScanStrings | scanner.ScanComments | scanner.SkipComments
	// build.zig.zon is Zig, not Go, so the occasional token won't lex. Swallow those
	// errors rather than printing them to stderr; the parser skips what it can't read.
	p.scanner.Error = func(*scanner.Scanner, string) {}
	p.advance()
	return p
}

// advance reads the next token.
func (p *parser) advance() {
	p.tok = p.scanner.Scan()
	p.text = p.scanner.TokenText()
	// Zig multiline strings (\\...) run to the end of the line and may contain any
	// character, including quotes and braces. Consume them at the character level so
	// they can't unbalance the parse.
	for p.tok == '\\' {
		for c := p.scanner.Next(); c != '\n' && c != scanner.EOF; {
			c = p.scanner.Next()
		}
		p.tok = p.scanner.Scan()
		p.text = p.scanner.TokenText()
	}
	p.tokens++
}

// parseName reads a field or enum name: a bare identifier, or the @"..." form Zig uses
// for names that aren't valid identifiers.
func (p *parser) parseName() (string, bool) {
	switch p.tok {
	case scanner.Ident:
		name := p.text
		p.advance()
		return name, true
	case '@':
		p.advance()
		if p.tok == scanner.String {
			name := unquote(p.text)
			p.advance()
			return name, true
		}
	}
	return "", false
}

// parseValue parses a single value and leaves the parser on the token after it.
func (p *parser) parseValue() *zonValue {
	if p.err != nil {
		return nil
	}
	switch p.tok {
	case scanner.EOF:
		return nil
	case scanner.String, scanner.RawString:
		v := &zonValue{kind: kindString, text: unquote(p.text)}
		p.advance()
		return v
	case '{':
		// Not valid ZON, which writes blocks as .{ ... }, but parse it anyway.
		return p.parseBlock()
	case '.':
		p.advance()
		if p.tok == '{' {
			return p.parseBlock()
		}
		if name, ok := p.parseName(); ok {
			return &zonValue{kind: kindEnum, text: name}
		}
		return &zonValue{kind: kindOther}
	default:
		p.advance()
		return &zonValue{kind: kindOther}
	}
}

// parseBlock parses a { ... } block, which may hold named fields (.key = value),
// unnamed elements, or both. The parser must be positioned on the opening brace.
func (p *parser) parseBlock() *zonValue {
	if p.depth >= maxDepth {
		p.err = errors.New("nesting is too deep")
		return nil
	}
	p.depth++
	defer func() { p.depth-- }()

	p.advance() // Consume '{'.
	block := &zonValue{kind: kindBlock}
	for p.err == nil && p.tok != '}' && p.tok != scanner.EOF {
		before := p.tokens
		switch p.tok {
		case ',':
			p.advance()
		case '.':
			p.advance()
			if p.tok == '{' {
				block.items = append(block.items, p.parseBlock())
				break
			}
			name, ok := p.parseName()
			if !ok {
				// A stray dot, already consumed.
				break
			}
			if p.tok != '=' {
				// An enum literal used as an element, e.g. .{ .foo, .bar }.
				block.items = append(block.items, &zonValue{kind: kindEnum, text: name})
				break
			}
			p.advance() // Consume '='.
			block.fields = append(block.fields, zonField{key: name, value: p.parseValue()})
		default:
			block.items = append(block.items, p.parseValue())
		}
		if p.tokens == before {
			// Nothing was consumed this round, so skip a token. The cases above always
			// consume, but this means malformed input can never spin forever.
			p.advance()
		}
	}
	if p.tok == '}' {
		p.advance()
	}
	return block
}

// unquote strips the quotes from a string literal and resolves its escape sequences.
// Zig's escapes are a subset of Go's apart from \u{...}; literals that don't unquote
// cleanly fall back to their raw contents.
func unquote(literal string) string {
	if s, err := strconv.Unquote(literal); err == nil {
		return s
	}
	return strings.TrimSuffix(strings.TrimPrefix(literal, `"`), `"`)
}

// parseZON parses the top-level struct literal of a build.zig.zon file.
func parseZON(r io.Reader) (*zonValue, error) {
	p := newParser(r)
	root := p.parseValue()
	if p.err != nil {
		return nil, p.err
	}
	if root == nil || root.kind != kindBlock {
		return nil, nil
	}
	return root, nil
}
