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
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

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
)

// defaultProfiles are the profiles Leiningen applies without being asked:
// :default expands to [:base :system :user :provided :dev], and :test is
// added when running tests. Other profiles, such as version matrices like
// :1.10 or tooling like :benchmark, are only active under an explicit
// `lein with-profile`, and `lein pom` leaves them out too, so their
// dependencies are not reported unless a default profile includes them by
// name; see addProfile.
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
// A profile is a map, the name of another profile, or a composite vector of
// both, as in :dev [:project/dev {:dependencies [...]}].
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
	r := newReader(input.Reader)
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
			if name, value, ok := stringDef(f); ok {
				defs[name] = value
			}
		case "defproject":
			return inventory.Inventory{Packages: packagesFromProject(f, defs, input.Path)}, nil
		}
	}
}

// stringDef reads (def name "value") or (def name "docstring" "value").
func stringDef(def *form) (name, value string, ok bool) {
	args := def.children[1:]
	if len(args) != 2 && len(args) != 3 {
		return "", "", false
	}
	if args[0].kind != kindSymbol {
		return "", "", false
	}
	for _, arg := range args[1:] {
		if arg.kind != kindString {
			return "", "", false
		}
	}
	return args[0].text, args[len(args)-1].text, true
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

	c := &collector{
		packages: []*extractor.Package{},
		seen:     map[string]*javalockfile.Metadata{},
		reported: map[*form]*javalockfile.Metadata{},
		path:     path,
	}
	for _, dep := range vectorElems(opts[":dependencies"]) {
		c.add(dep, defs, managed, "")
	}

	// :profiles {:dev {:dependencies [...]}, :uberjar {:aot :all}}
	if profiles := opts[":profiles"]; profiles != nil && profiles.kind == kindMap {
		byName := map[string]*form{}
		var active []string
		for i := 0; i+1 < len(profiles.children); i += 2 {
			key := profiles.children[i]
			if key.kind != kindKeyword {
				continue
			}
			name := strings.TrimPrefix(key.text, ":")
			if _, dup := byName[name]; !dup && defaultProfiles[name] {
				active = append(active, name)
			}
			byName[name] = profiles.children[i+1]
		}
		for _, name := range active {
			c.addProfile(name, byName, defs, managed)
		}
	}

	return c.packages
}

type collector struct {
	packages []*extractor.Package
	// seen holds what has been reported, to drop exact repetitions.
	seen map[string]*javalockfile.Metadata
	// reported maps a dependency vector to the metadata of its package.
	reported map[*form]*javalockfile.Metadata
	path     string
}

// addProfile reports the dependencies of the default profile name, with the
// name as their dependency group.
//
// A profile is a map, the name of another profile, or a composite vector of
// both. Leiningen resolves the names recursively against :profiles
// (lookup-profile in leiningen.core.project), so they are followed here too
// and what they declare is reported as part of the profile that includes
// them. Names that this file does not define, such as :profiles/dev from a
// developer's own profiles.clj, contribute nothing. Other default profiles
// are not followed: they are reported under their own name. A dependency
// that several default profiles include this way is reported once, with all
// of them as its groups.
func (c *collector) addProfile(name string, profiles map[string]*form, defs, managed map[string]string) {
	// Each name is expanded once, which also ends reference cycles.
	visited := map[string]bool{name: true}
	pending := []*form{profiles[name]}
	for len(pending) > 0 {
		f := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		switch f.kind {
		case kindMap:
			for _, dep := range vectorElems(keywordPairs(f.children, 0)[":dependencies"]) {
				c.add(dep, defs, managed, name)
			}
		case kindVector:
			// Pushed in reverse so that the parts are handled in the order
			// they are written.
			for i := len(f.children) - 1; i >= 0; i-- {
				pending = append(pending, f.children[i])
			}
		case kindKeyword:
			ref := strings.TrimPrefix(f.text, ":")
			if visited[ref] || defaultProfiles[ref] {
				continue
			}
			visited[ref] = true
			if p := profiles[ref]; p != nil {
				pending = append(pending, p)
			}
		}
	}
}

// add reports one dependency vector. profile is empty for the top-level
// :dependencies and the profile name otherwise.
func (c *collector) add(dep *form, defs, managed map[string]string, profile string) {
	d, ok := parseDependency(dep, defs, managed)
	if !ok || d.version == "" {
		// Without a version there is nothing to match against advisories.
		return
	}

	if md, ok := c.reported[dep]; ok {
		// The same declaration, reached again through another profile.
		if !slices.Contains(md.DepGroupVals, profile) {
			md.DepGroupVals = append(md.DepGroupVals, profile)
		}
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
	if md, ok := c.seen[key]; ok {
		c.reported[dep] = md
		return
	}

	md := &javalockfile.Metadata{
		ArtifactID:   d.artifact,
		GroupID:      d.group,
		Type:         d.extension,
		Classifier:   d.classifier,
		DepGroupVals: groups,
	}
	c.seen[key] = md
	c.reported[dep] = md
	c.packages = append(c.packages, &extractor.Package{
		Name:     name,
		Version:  d.version,
		PURLType: purl.TypeMaven,
		Metadata: md,
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
