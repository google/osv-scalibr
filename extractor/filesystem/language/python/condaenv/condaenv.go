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

// Package condaenv extracts packages from Conda environment.yml files.
//
// environment.yml (or environment.yaml) is the declarative format Conda uses
// to share and recreate an environment. It is committed next to the source
// code in repositories, container build contexts and CI configs, e.g.
//
//	name: ml-research
//	channels:
//	  - conda-forge
//	dependencies:
//	  - python=3.10
//	  - scipy=1.9.0
//	  - pip:
//	    - torch==1.13.0
//
// This is distinct from python/condameta, which reads the conda-meta/*.json
// files of an installed environment and therefore only reports packages on a
// live Conda installation.
//
// Both the Conda dependencies and the packages of the nested pip: section are
// reported with the PyPI PURL type. OSV has no Conda ecosystem, and
// python/condameta maps Conda packages to PyPI for the same reason. Conda
// package names are usually identical to their PyPI counterparts, but not
// always (the Conda pytorch package is torch on PyPI, for example), so some
// packages can stay unmatched.
//
// Only dependencies that pin a single version are reported. A range such as
// scipy>=1.9.0 doesn't identify the version that ends up installed, so
// reporting one of its bounds as the version would be a guess.
package condaenv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"gopkg.in/yaml.v3"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/condaenv"

	// defaultMaxFileSizeBytes is the default maximum file size the extractor
	// will attempt to extract. If a file is encountered that is larger than
	// this limit, the file is ignored by FileRequired.
	defaultMaxFileSizeBytes = 10 * units.MiB
)

var (
	// nameRe matches a Conda package name, which is also a valid PyPI
	// distribution name.
	nameRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

	// versionRe matches the versions Conda and pip accept, i.e. PEP 440 style
	// versions plus the epoch and local version separators.
	versionRe = regexp.MustCompile(`^[0-9][A-Za-z0-9.!+_-]*$`)
)

// Extractor extracts packages from Conda environment.yml files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Conda environment.yml extractor.
//
// For most use cases, initialize with:
// ```
// e := New(&cpb.PluginConfig{})
// ```
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSize := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSize = cfg.GetMaxFileSizeBytes()
	}
	return &Extractor{maxFileSizeBytes: maxFileSize}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the file is named environment.yml or
// environment.yaml, the two file names Conda uses for environment
// specifications.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if !strings.HasSuffix(path, ".yml") && !strings.HasSuffix(path, ".yaml") {
		return false
	}
	base := filepath.Base(filepath.ToSlash(path))
	if base != "environment.yml" && base != "environment.yaml" {
		return false
	}

	fi, err := api.Stat()
	if err != nil {
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

// Extract extracts the Conda and pip dependencies of the environment
// specification passed through the scan input.
func (e Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := parse(input.Reader, input.Path)
	e.reportFileExtracted(input.Path, input.Info, err)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("condaenv.parse(%q): %w", input.Path, err)
	}
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

func parse(r io.Reader, path string) ([]*extractor.Package, error) {
	var root yaml.Node
	// Decode into a Node instead of a struct to keep the line number of every
	// dependency for the reported location.
	if err := yaml.NewDecoder(r).Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			// The file is empty, which is not an environment specification but
			// also not an error.
			return nil, nil
		}
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}
	if len(root.Content) == 0 {
		return nil, nil
	}

	deps := mappingValue(root.Content[0], "dependencies")
	if deps == nil || deps.Kind != yaml.SequenceNode {
		// Not an environment specification, or one without dependencies.
		return nil, nil
	}
	return packagesFromDependencies(deps, path), nil
}

// packagesFromDependencies extracts the packages of the dependencies: section,
// covering both the Conda match specs and the pip: subsection.
func packagesFromDependencies(deps *yaml.Node, path string) []*extractor.Package {
	var pkgs []*extractor.Package
	for _, dep := range deps.Content {
		if dep.Kind == yaml.ScalarNode {
			if pkg := condaPackage(dep, path); pkg != nil {
				pkgs = append(pkgs, pkg)
			}
			continue
		}
		// pip is the only subsection Conda supports inside dependencies.
		if dep.Kind == yaml.MappingNode {
			pkgs = append(pkgs, pipPackages(mappingValue(dep, "pip"), path)...)
		}
	}
	return pkgs
}

func condaPackage(node *yaml.Node, path string) *extractor.Package {
	name, version := parseCondaSpec(node.Value)
	if name == "" || version == "" {
		return nil
	}
	// The python entry declares the interpreter version of the environment, so
	// reporting it as the PyPI distribution of the same name would be a wrong
	// identity.
	if name == "python" {
		return nil
	}
	return newPackage(name, version, path, node.Line)
}

func pipPackages(pip *yaml.Node, path string) []*extractor.Package {
	if pip == nil || pip.Kind != yaml.SequenceNode {
		return nil
	}
	var pkgs []*extractor.Package
	for _, req := range pip.Content {
		if req.Kind != yaml.ScalarNode {
			continue
		}
		name, version := parsePipRequirement(req.Value)
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, newPackage(name, version, path, req.Line))
	}
	return pkgs
}

func newPackage(name, version, path string, line int) *extractor.Package {
	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purl.TypePyPi,
		Location: extractor.LocationFromPathAndLine(path, line),
	}
}

// parseCondaSpec parses a Conda match spec, e.g. conda-forge::numpy=1.26.0 or
// numpy=1.26.0=py311h64a7726_0. It returns empty strings for specs that don't
// pin a single version, e.g. numpy or numpy>=1.26.
func parseCondaSpec(spec string) (name string, version string) {
	spec = strings.TrimSpace(spec)
	// Drop the optional channel, e.g. conda-forge::numpy=1.26.0.
	if _, after, ok := strings.Cut(spec, "::"); ok {
		spec = after
	}
	// Match specs can also be space separated, in which case the second field
	// is the version, e.g. numpy 1.26.0 py311h64a7726_0.
	if fields := strings.Fields(spec); len(fields) > 1 {
		return pinned(fields[0], fields[1])
	}

	name, rest, ok := strings.Cut(spec, "=")
	if !ok {
		// No version constraint at all, e.g. numpy.
		return "", ""
	}
	// numpy==1.26.0 pins the same version as numpy=1.26.0. Every other
	// operator stays part of the name and is rejected by cleanName, which is
	// how ranges such as numpy>=1.26 are skipped.
	rest = strings.TrimLeft(rest, "=")
	// The build string is the third field of a match spec and is not part of
	// the version, e.g. numpy=1.26.0=py311h64a7726_0.
	version, _, _ = strings.Cut(rest, "=")
	return pinned(name, version)
}

// parsePipRequirement parses a requirement of the pip: subsection, e.g.
// torch==1.13.0. It returns empty strings for requirements that don't pin a
// single version, e.g. pip options, direct references and ranges.
func parsePipRequirement(req string) (name string, version string) {
	req = strings.TrimSpace(req)
	// Options such as -r extra-requirements.txt or --index-url don't name a
	// package.
	if strings.HasPrefix(req, "-") {
		return "", ""
	}
	// Direct references and local paths, e.g. torch @ https://host/t.whl,
	// git+https://host/repo.git or ../lib, carry no PyPI version.
	if strings.ContainsAny(req, "@/") {
		return "", ""
	}
	// Drop the environment marker, e.g. torch==1.13.0; python_version<"3.11".
	req, _, _ = strings.Cut(req, ";")

	name, rest, ok := strings.Cut(req, "==")
	if !ok {
		return "", ""
	}
	// === is pip's arbitrary equality operator and pins a version as well.
	rest = strings.TrimPrefix(rest, "=")
	// A compound specifier such as ==1.13.0,!=1.13.1 doesn't pin a version.
	if strings.Contains(rest, ",") {
		return "", ""
	}
	return pinned(name, rest)
}

// pinned returns the cleaned up name and version of a dependency, or empty
// strings if either of them isn't a name and version OSV can be queried with.
func pinned(name string, version string) (string, string) {
	name, version = cleanName(name), cleanVersion(version)
	if name == "" || version == "" {
		return "", ""
	}
	return name, version
}

func cleanName(name string) string {
	name = strings.TrimSpace(name)
	// Drop the extras of a pip requirement, e.g. celery[redis].
	if i := strings.IndexByte(name, '['); i >= 0 {
		name = name[:i]
	}
	if !nameRe.MatchString(name) {
		return ""
	}
	return name
}

func cleanVersion(version string) string {
	version = strings.TrimSpace(version)
	// Conda and pip treat a trailing wildcard as any version of that series,
	// e.g. 1.26.* or 1.26.0.*. The series itself is the closest version OSV
	// can match on.
	version = strings.TrimSuffix(version, ".*")
	version = strings.TrimSuffix(version, "*")
	if !versionRe.MatchString(version) {
		return ""
	}
	return version
}

// mappingValue returns the value node associated with key in a YAML mapping
// node, or nil if the key isn't present.
func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	// MappingNode content alternates [key, value, key, value, ...].
	for i := 0; i+1 < len(node.Content); i += 2 {
		k := node.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

var _ filesystem.Extractor = Extractor{}
