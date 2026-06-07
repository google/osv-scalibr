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

// Package htmlcdn extracts NPM package versions in JavaScript CDN URLs
package htmlcdn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"deps.dev/util/semver"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"

	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "javascript/htmlcdn"

	// defaultMaxFileSizeBytes is the default maximum file size the extractor will
	// attempt to extract. If a file is encountered that is larger than this
	// limit, the file is ignored by `FileRequired`.
	defaultMaxFileSizeBytes = 100 * units.MiB
)

var (
	jsDelivrPathRegex    = regexp.MustCompile(`/npm/(@[^@/]+/[^@/]+|[^@/]+)(@([^/]+))?`)
	unpkgPathRegex       = regexp.MustCompile(`/(@[^@/]+/[^@/]+|[^@/]+)(@([^/]+))?`)
	likelyHTMLExtensions = []string{
		// Go templates
		".tmpl",
		".tpl",
		// Common Python templating languages
		".jinja",
		".jinja2",
		".j2",
		// PHP
		".php",
		// Common C# HTML extensions
		".asp",
		".aspx",
		".ascx",
		".razor",
		".master",
		// JSP
		".jsp",
		".jspx",
		".jspf",
	}
)

// Extractor extracts javascript packages from package.json files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a package.json extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	return &Extractor{
		maxFileSizeBytes: maxFileSizeBytes,
	}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file is an HTML like file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()

	if !isLikelyHTMLExtension(filepath.Ext(path)) {
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

func isLikelyHTMLExtension(extension string) bool {
	extension = strings.ToLower(extension)

	return strings.Contains(extension, "htm") || slices.Contains(likelyHTMLExtensions, extension)
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

// Extract extracts packages from package.json files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	packages, err := parse(input.Path, input.Reader)

	if err != nil {
		e.reportFileExtracted(input.Path, input.Info, err)
		return inventory.Inventory{}, fmt.Errorf("htmlcdn.parse: %w", err)
	}

	for _, pkg := range packages {
		pkg.Location = extractor.LocationFromPath(input.Path)
	}

	e.reportFileExtracted(input.Path, input.Info, nil)
	return inventory.Inventory{Packages: packages}, nil
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

func parse(path string, r io.Reader) ([]*extractor.Package, error) {
	packages := make([]*extractor.Package, 0)
	tokenizer := html.NewTokenizer(r)

	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			err := tokenizer.Err()
			if errors.Is(err, io.EOF) {
				return packages, nil
			}
			return packages, err
		case html.StartTagToken:
			token := tokenizer.Token()
			if token.DataAtom == atom.Script {
				pkgs, err := parseScriptTag(path, &token, tokenizer)
				packages = slices.Concat(packages, pkgs)

				if err != nil {
					return packages, err
				}
			}
		}
	}
}

func parseScriptTag(filePath string, token *html.Token, tokenizer *html.Tokenizer) ([]*extractor.Package, error) {
	for _, attr := range token.Attr {
		if attr.Namespace != "" {
			continue
		}

		if attr.Key == "type" && attr.Val == "importmap" {
			for {
				tok := tokenizer.Next()

				switch tok {
				case html.ErrorToken:
					err := tokenizer.Err()
					if errors.Is(err, io.EOF) {
						return []*extractor.Package{}, nil
					}
					return []*extractor.Package{}, err
				case html.EndTagToken:
				case html.StartTagToken:
				case html.SelfClosingTagToken:
					return []*extractor.Package{}, nil
				case html.TextToken:
					token := tokenizer.Token()
					return parseImportMap(filePath, token.Data), nil
				default:
					continue
				}
			}
		} else if attr.Key == "src" {
			return parseSrcURL(filePath, attr.Val), nil
		}
	}
	return []*extractor.Package{}, nil
}

func parseSrcURL(filePath string, src string) []*extractor.Package {
	scriptURL, err := url.Parse(src)

	if err != nil {
		return []*extractor.Package{}
	}

	// Overly cautious measure to prevent potential credentials from being leaked.
	scriptURL.User = nil

	if !slices.Contains([]string{"http", "https"}, scriptURL.Scheme) {
		return []*extractor.Package{}
	}

	if !slices.Contains([]string{"", "80", "443"}, scriptURL.Port()) {
		return []*extractor.Package{}
	}

	if scriptURL.Host == "cdn.jsdelivr.net" {
		return parseJsDelivrCdnPath(filePath, scriptURL)
	}
	if scriptURL.Host == "esm.run" {
		return parseEsmRunCdnPath(filePath, scriptURL)
	}
	if slices.Contains([]string{"unpkg.com", "esm.unpkg.com"}, scriptURL.Host) {
		return parseUnpkgCdnPath(filePath, scriptURL)
	}
	return []*extractor.Package{}
}

type importMap struct {
	Imports map[string]string            `json:"imports"`
	Scopes  map[string]map[string]string `json:"scopes"`
}

func parseImportMap(filePath string, importmap string) []*extractor.Package {
	var data importMap

	// TODO: be more forgiving (support trailing commas and comments)
	err := json.Unmarshal([]byte(importmap), &data)

	if err != nil {
		return []*extractor.Package{}
	}

	packages := make([]*extractor.Package, 0)

	for _, url := range data.Imports {
		packages = slices.Concat(packages, parseSrcURL(filePath, url))
	}

	for _, scopes := range data.Scopes {
		for _, scope := range scopes {
			packages = slices.Concat(packages, parseSrcURL(filePath, scope))
		}
	}

	return packages
}

func parseJsDelivrCdnPath(filePath string, url *url.URL) []*extractor.Package {
	if strings.HasSuffix(url.Path, "/") {
		return []*extractor.Package{}
	}

	matches := jsDelivrPathRegex.FindStringSubmatch(url.Path)

	if len(matches) != 4 {
		return []*extractor.Package{}
	}

	packageName := matches[1]
	version := matches[3]

	return parseNpmVersion(filePath, url, packageName, version)
}

func parseUnpkgCdnPath(filePath string, url *url.URL) []*extractor.Package {
	if strings.HasSuffix(url.Path, "/") {
		return []*extractor.Package{}
	}

	matches := unpkgPathRegex.FindStringSubmatch(url.Path)

	if len(matches) != 4 {
		return []*extractor.Package{}
	}

	packageName := matches[1]
	version := matches[3]

	return parseNpmVersion(filePath, url, packageName, version)
}

func parseEsmRunCdnPath(filePath string, url *url.URL) []*extractor.Package {
	// Because esm.run and unpkg.com use the same file path syntax, we can reuse the same function.
	return parseUnpkgCdnPath(filePath, url)
}

func parseNpmVersion(filePath string, url *url.URL, packageName string, rawVersion string) []*extractor.Package {
	version := rawVersion

	if slices.Contains([]string{"", "latest"}, version) {
		version = "x.x.x"
	}

	constraint, err := semver.NPM.ParseConstraint(version)

	if err != nil {
		log.Debugf("failed to parse NPM version %s for dependency %s in %s: %v", version, packageName, filePath, err)
		return []*extractor.Package{}
	}

	npmVersion, err := constraint.CalculateMinVersion()

	if err != nil {
		log.Debugf("failed to parse NPM version constraint %s for dependency %s in %s: %v", version, packageName, filePath, err)
		return []*extractor.Package{}
	}

	return []*extractor.Package{
		&extractor.Package{
			Name: packageName,
			// Need to use Canon() to rebuild the string with the changes from CalculateMinVersion.
			// Ignoring the build value, which isn't relevant for version comparison.
			// TODO(b/444684673): Include the build value in the version string. Currently deps.dev
			// does not parse out the build value, so that need to be fixed first.
			Version:  npmVersion.Canon(false),
			PURLType: purl.TypeNPM,
			Location: extractor.LocationFromPath(filePath),
			Metadata: &Metadata{
				RawVersion: rawVersion,
				FullURL:    url.String(),
			},
		},
	}
}
