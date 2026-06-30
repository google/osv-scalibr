// Package depsedn extracts Maven dependencies from Clojure deps.edn files.
package depsedn

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "clojure/depsedn"
)

// Extractor extracts Maven packages from Clojure deps.edn files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (Extractor) Name() string { return Name }

// Version of the extractor.
func (Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches Clojure deps.edn files.
func (Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "deps.edn"
}

// Extract extracts packages from Clojure deps.edn files passed through the scan input.
func (Extractor) Extract(
	_ context.Context,
	input *filesystem.ScanInput,
) (inventory.Inventory, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read input: %w", err)
	}

	deps := parseMavenDeps(stripComments(content))
	packages := make([]*extractor.Package, 0, len(deps))
	seen := map[string]bool{}

	for _, dep := range deps {
		groupID, artifactID := splitLib(dep.lib)
		if groupID == "" || artifactID == "" || dep.version == "" {
			continue
		}

		key := groupID + ":" + artifactID + "@" + dep.version
		if seen[key] {
			continue
		}
		seen[key] = true

		line := 1 + bytes.Count(content[:dep.offset], []byte("\n"))
		packages = append(packages, &extractor.Package{
			Name:     groupID + ":" + artifactID,
			Version:  dep.version,
			PURLType: purl.TypeMaven,
			Metadata: &javalockfile.Metadata{
				ArtifactID: artifactID,
				GroupID:    groupID,
			},
			Location: extractor.LocationFromPathAndLine(input.Path, line),
		})
	}

	return inventory.Inventory{Packages: packages}, nil
}

type mavenDep struct {
	lib     string
	version string
	offset  int
}

func parseMavenDeps(content []byte) []mavenDep {
	deps := []mavenDep{}
	position := 0
	for position < len(content) {
		position = skipWhitespace(content, position)
		if position >= len(content) {
			break
		}
		switch content[position] {
		case '"':
			position = skipString(content, position)
			continue
		case '{', '[', '(':
			position++
			continue
		case '}', ']', ')':
			position++
			continue
		}

		token, nextPosition := readToken(content, position)
		if token == "" {
			position++
			continue
		}
		position = nextPosition
		if !isDependencyMapKey(token) {
			continue
		}

		position = skipWhitespace(content, position)
		if position >= len(content) || content[position] != '{' {
			continue
		}
		dependencyMapDeps, mapEnd := parseDependencyMap(content, position)
		deps = append(deps, dependencyMapDeps...)
		if mapEnd == -1 {
			break
		}
		position = mapEnd + 1
	}
	return deps
}

func parseDependencyMap(content []byte, mapStart int) ([]mavenDep, int) {
	mapEnd := matchingDelimiter(content, mapStart)
	if mapEnd == -1 {
		return nil, -1
	}

	deps := []mavenDep{}
	position := mapStart + 1
	for position < mapEnd {
		position = skipWhitespace(content, position)
		if position >= mapEnd {
			break
		}

		libStart := position
		lib, nextPosition := readToken(content, position)
		if !isLibraryToken(lib) {
			position = skipForm(content, position)
			continue
		}

		position = skipWhitespace(content, nextPosition)
		if position >= mapEnd {
			break
		}
		if content[position] != '{' {
			position = skipForm(content, position)
			continue
		}

		valueEnd := matchingDelimiter(content, position)
		if valueEnd == -1 {
			return deps, mapEnd
		}
		if version, ok := findMvnVersion(content[position+1 : valueEnd]); ok {
			deps = append(deps, mavenDep{
				lib:     lib,
				version: version,
				offset:  libStart,
			})
		}
		position = valueEnd + 1
	}
	return deps, mapEnd
}

func isDependencyMapKey(token string) bool {
	switch token {
	case ":deps", ":extra-deps", ":replace-deps", ":override-deps", ":default-deps":
		return true
	default:
		return false
	}
}

func isLibraryToken(token string) bool {
	return token != "" && !strings.HasPrefix(token, ":") &&
		!strings.HasPrefix(token, "#")
}

func stripComments(content []byte) []byte {
	stripped := bytes.Clone(content)
	inString := false
	escaped := false

	for index, currentByte := range stripped {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			switch currentByte {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}

		switch currentByte {
		case '"':
			inString = true
		case ';':
			for commentIndex := index; commentIndex < len(stripped) &&
				stripped[commentIndex] != '\n'; commentIndex++ {
				stripped[commentIndex] = ' '
			}
		}
	}

	return stripped
}

func findMvnVersion(mapBody []byte) (string, bool) {
	position := 0
	depth := 0
	for position < len(mapBody) {
		position = skipWhitespace(mapBody, position)
		if position >= len(mapBody) {
			break
		}
		switch mapBody[position] {
		case '{', '[', '(':
			depth++
			position++
			continue
		case '}', ']', ')':
			if depth > 0 {
				depth--
			}
			position++
			continue
		case '"':
			position = skipString(mapBody, position)
			continue
		}

		token, nextPosition := readToken(mapBody, position)
		if token == "" {
			position++
			continue
		}
		position = nextPosition
		if depth == 0 && token == ":mvn/version" {
			position = skipWhitespace(mapBody, position)
			version, nextPosition, ok := readString(mapBody, position)
			if !ok {
				return "", false
			}
			_ = nextPosition
			return version, true
		}
	}
	return "", false
}

func splitLib(lib string) (string, string) {
	lib = strings.TrimSpace(lib)
	groupID, artifactID, ok := strings.Cut(lib, "/")
	if !ok {
		return lib, lib
	}
	return groupID, artifactID
}

func skipForm(content []byte, position int) int {
	if position >= len(content) {
		return position
	}
	if content[position] == '"' {
		return skipString(content, position)
	}
	if isOpeningDelimiter(content[position]) {
		end := matchingDelimiter(content, position)
		if end == -1 {
			return len(content)
		}
		return end + 1
	}
	_, nextPosition := readToken(content, position)
	if nextPosition == position {
		return position + 1
	}
	return nextPosition
}

func skipWhitespace(content []byte, position int) int {
	for position < len(content) {
		currentRune := rune(content[position])
		if content[position] != ',' && !unicode.IsSpace(currentRune) {
			break
		}
		position++
	}
	return position
}

func readToken(content []byte, position int) (string, int) {
	start := position
	for position < len(content) && !isTokenDelimiter(content[position]) {
		position++
	}
	return string(content[start:position]), position
}

func readString(content []byte, position int) (string, int, bool) {
	if position >= len(content) || content[position] != '"' {
		return "", position, false
	}
	start := position + 1
	position++
	escaped := false
	for position < len(content) {
		currentByte := content[position]
		if escaped {
			escaped = false
			position++
			continue
		}
		switch currentByte {
		case '\\':
			escaped = true
		case '"':
			return string(content[start:position]), position + 1, true
		}
		position++
	}
	return "", position, false
}

func skipString(content []byte, position int) int {
	_, nextPosition, ok := readString(content, position)
	if !ok {
		return len(content)
	}
	return nextPosition
}

func matchingDelimiter(content []byte, position int) int {
	if position >= len(content) || !isOpeningDelimiter(content[position]) {
		return -1
	}
	stack := []byte{content[position]}
	position++
	for position < len(content) {
		currentByte := content[position]
		if currentByte == '"' {
			position = skipString(content, position)
			continue
		}
		if isOpeningDelimiter(currentByte) {
			stack = append(stack, currentByte)
			position++
			continue
		}
		if isClosingDelimiter(currentByte) {
			if len(stack) == 0 || !matchesDelimiter(stack[len(stack)-1], currentByte) {
				return -1
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return position
			}
		}
		position++
	}
	return -1
}

func isTokenDelimiter(currentByte byte) bool {
	return currentByte == ',' || currentByte == '"' || currentByte == ';' ||
		isOpeningDelimiter(currentByte) || isClosingDelimiter(currentByte) ||
		unicode.IsSpace(rune(currentByte))
}

func isOpeningDelimiter(currentByte byte) bool {
	return currentByte == '{' || currentByte == '[' || currentByte == '('
}

func isClosingDelimiter(currentByte byte) bool {
	return currentByte == '}' || currentByte == ']' || currentByte == ')'
}

func matchesDelimiter(opening byte, closing byte) bool {
	return (opening == '{' && closing == '}') ||
		(opening == '[' && closing == ']') ||
		(opening == '(' && closing == ')')
}

var _ filesystem.Extractor = Extractor{}
