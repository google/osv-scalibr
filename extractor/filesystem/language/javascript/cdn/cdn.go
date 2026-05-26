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

// Package cdn extracts NPM packages loaded from JavaScript CDN URLs in HTML.
package cdn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"golang.org/x/net/html"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "javascript/cdn"

	// defaultMaxFileSizeBytes is the default maximum file size the extractor
	// will attempt to extract.
	defaultMaxFileSizeBytes = 10 * units.MiB
)

var (
	semverStartRe = regexp.MustCompile(`^\d`)
	npmNameRe     = regexp.MustCompile(`^(@[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|[A-Za-z0-9_.-]+)$`)
)

// Extractor extracts NPM package references from JavaScript CDN URLs in HTML.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

type importMap struct {
	Imports map[string]string            `json:"imports"`
	Scopes  map[string]map[string]string `json:"scopes"`
}

// New returns a JavaScript CDN extractor.
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

// FileRequired returns true if the specified file is an HTML file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := filepath.ToSlash(api.Path())
	if !slices.Contains([]string{".html", ".htm"}, strings.ToLower(filepath.Ext(path))) {
		return false
	}

	fi, err := api.Stat()
	if err != nil {
		return false
	}
	if fi.IsDir() {
		return false
	}
	if e.maxFileSizeBytes > 0 && fi.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fi.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fi.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts NPM packages from JavaScript CDN URLs in an HTML file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := parse(ctx, input.Reader, input.Path)
	if err != nil {
		e.reportFileExtracted(input.Path, input.Info, err)
		return inventory.Inventory{}, fmt.Errorf("cdn.parse(%q): %w", input.Path, err)
	}

	e.reportFileExtracted(input.Path, input.Info, nil)
	return inventory.Inventory{Packages: pkgs}, nil
}

func (e Extractor) reportFileExtracted(path string, fileinfo fs.FileInfo, err error) {
	if e.Stats == nil {
		return
	}
	var fileSizeBytes int64
	if fileinfo != nil {
		fileSizeBytes = fileinfo.Size()
	}
	e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
		Path:          path,
		Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
		FileSizeBytes: fileSizeBytes,
	})
}

func parse(ctx context.Context, r io.Reader, path string) ([]*extractor.Package, error) {
	doc, err := html.Parse(r)
	if err != nil {
		return nil, fmt.Errorf("html parse: %w", err)
	}

	var urls []string
	var walk func(*html.Node) error
	walk = func(n *html.Node) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "script") {
			if src := attr(n, "src"); src != "" {
				urls = append(urls, src)
			}
			if strings.EqualFold(attr(n, "type"), "importmap") {
				urls = append(urls, importMapURLs(scriptText(n))...)
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(doc); err != nil {
		return nil, err
	}

	var pkgs []*extractor.Package
	for _, rawURL := range urls {
		if pkg := packageFromURL(rawURL, path); pkg != nil {
			pkgs = append(pkgs, pkg)
		}
	}
	return dedupePackages(pkgs), nil
}

func attr(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val
		}
	}
	return ""
}

func scriptText(n *html.Node) string {
	var b strings.Builder
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.TextNode {
			b.WriteString(child.Data)
		}
	}
	return b.String()
}

func importMapURLs(raw string) []string {
	var im importMap
	if err := json.Unmarshal([]byte(raw), &im); err != nil {
		return nil
	}

	var urls []string
	for _, spec := range im.Imports {
		urls = append(urls, spec)
	}
	for _, scopeImports := range im.Scopes {
		for _, spec := range scopeImports {
			urls = append(urls, spec)
		}
	}
	return urls
}

func packageFromURL(rawURL string, path string) *extractor.Package {
	name, version, ok := packageNameVersionFromURL(rawURL)
	if !ok {
		return nil
	}
	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purl.TypeNPM,
		Location: extractor.LocationFromPath(path),
	}
}

func packageNameVersionFromURL(rawURL string) (string, string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", false
	}
	if u.Scheme != "https" {
		return "", "", false
	}

	trimmedPath := strings.TrimPrefix(u.EscapedPath(), "/")
	var spec string
	switch strings.ToLower(u.Hostname()) {
	case "unpkg.com", "esm.run":
		spec = trimmedPath
	case "cdn.jsdelivr.net":
		if !strings.HasPrefix(trimmedPath, "npm/") {
			return "", "", false
		}
		spec = strings.TrimPrefix(trimmedPath, "npm/")
	default:
		return "", "", false
	}
	return splitNPMSpec(spec)
}

func splitNPMSpec(spec string) (string, string, bool) {
	spec, err := url.PathUnescape(spec)
	if err != nil {
		return "", "", false
	}
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.HasPrefix(spec, ".") || strings.Contains(spec, "://") {
		return "", "", false
	}

	name, rest, ok := splitNameAndRest(spec)
	if !ok || !npmNameRe.MatchString(name) {
		return "", "", false
	}

	if !strings.HasPrefix(rest, "@") {
		return "", "", false
	}
	version := strings.TrimPrefix(rest, "@")
	if idx := strings.Index(version, "/"); idx >= 0 {
		version = version[:idx]
	}
	version = strings.TrimPrefix(version, "v")
	if version == "" || !semverStartRe.MatchString(version) {
		return "", "", false
	}
	return name, version, true
}

func splitNameAndRest(spec string) (string, string, bool) {
	if strings.HasPrefix(spec, "@") {
		slash := strings.Index(spec, "/")
		if slash <= 1 {
			return "", "", false
		}
		rest := spec[slash+1:]
		at := strings.Index(rest, "@")
		if at < 0 {
			return "", "", false
		}
		return spec[:slash+1+at], rest[at:], true
	}

	at := strings.Index(spec, "@")
	if at <= 0 {
		return "", "", false
	}
	return spec[:at], spec[at:], true
}

func dedupePackages(pkgs []*extractor.Package) []*extractor.Package {
	seen := map[string]bool{}
	var out []*extractor.Package
	for _, pkg := range pkgs {
		key := strings.Join([]string{
			pkg.PURLType,
			pkg.Name,
			pkg.Version,
			pkg.Location.PathOrEmpty(),
		}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, pkg)
	}
	return out
}
