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

// Package fromnpm implements an annotator for packages that were installed from the NPM
// repositories. This is used to determine if NPM package is a locally-published package or not to
// identify package name collisions on the NPM registry.
package fromnpm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/annotator"
	scanresultpb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/internal/dependencyfile/packagelockjson"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name of the Annotator.
	Name = "misc/from-npm"
	// nodeModulesDirectory is the NPM node_modules directory.
	nodeModulesDirectory = "node_modules"
	// npmRegistryURL is the NPM Registry URL.
	npmRegistryURL = "https://registry.npmjs.org/"
)

var (
	// lockfilesByPriority is the priority of the lockfile to use.
	// npm-shrinkwrap.json, if exists, npm will use it to install dependencies. When shrinkwrap is
	// not present, npm will look for package-lock.json. This is the default lockfile for the modern
	// npm versions. The hidden package-lock.json is generated based on the root-level package-lock.json.
	lockfilesByPriority = []string{"npm-shrinkwrap.json", "package-lock.json", ".package-lock.json"}
)

// Annotator adds annotations to NPM packages that are installed from the NPM repositories.
// This is used to determine if NPM package is a locally-published package or not to
// identify package name collisions on the NPM registry.
type Annotator struct{}

// New returns a new Annotator.
func New() annotator.Annotator { return &Annotator{} }

// Name of the annotator.
func (Annotator) Name() string { return "misc/from-npm" }

// Version of the annotator.
func (Annotator) Version() int { return 0 }

// Requirements of the annotator.
func (Annotator) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// Annotate adds annotations to NPM packages from /node_modules/../package.json that are installed from the NPM repositories.
func (a *Annotator) Annotate(ctx context.Context, input *annotator.ScanInput, results *inventory.Inventory) error {
	rootDirToPackages := MapNPMProjectRootsToPackages(results.Packages)
	var errs []error
	for rootDir, pkgs := range rootDirToPackages {
		registryResolvedMap, err := ResolvedFromLockfile(rootDir, input.ScanRoot.FS)
		if err != nil {
			// If no lockfile is found, we want to annotate the packages as locally published packages.
			errs = append(errs, fmt.Errorf("%s failed to resolve lockfile in %q: %w", a.Name(), rootDir, err))
		}
		for _, pkg := range pkgs {
			if pkg.Metadata == nil {
				pkg.Metadata = &scanresultpb.JavascriptPackageJSONMetadata{}
			}
			castedMetadata, ok := pkg.Metadata.(*scanresultpb.JavascriptPackageJSONMetadata)
			if !ok {
				errs = append(errs, fmt.Errorf("%s expected type *scanresultpb.JavascriptPackageJSONMetadata but got %T for package %q", a.Name(), pkg.Metadata, pkg.Name))
				continue
			}
			// If no lockfile is found, we assume they are locally published packages.
			castedMetadata.FromNpmRepository = registryResolvedMap != nil && registryResolvedMap[pkg.Name]
		}
	}
	return errors.Join(errs...)
}

// ResolvedFromLockfile looks for lockfiles in the given root directory and returns a map of package
// names in the lockfile and whether they were resolved from the NPM registry.
// If no lockfile is found, it returns an error.
// The first non-empty lockfile it finds per the priority list gets parsed and returned.
// For example, when given /tmp as root, it will look through the following lockfiles in this order:
// 1. /tmp/npm-shrinkwrap.json
// 2. /tmp/package-lock.json
// 3. /tmp/node_modules/.package-lock.json
func ResolvedFromLockfile(root string, fsys scalibrfs.FS) (map[string]bool, error) {
	var errs []error
	for _, lockfile := range lockfilesByPriority {
		lockfilePath := filepath.Join(root, lockfile)
		if lockfile == ".package-lock.json" {
			lockfilePath = filepath.Join(root, nodeModulesDirectory, ".package-lock.json")
		}

		parsedLockfile, err := npmLockfile(lockfilePath, fsys)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to resolve lockfile: %w", err))
			continue
		}
		return registryResolvedPackages(parsedLockfile), nil
	}
	return nil, errors.Join(errs...)
}

func registryResolvedPackages(lockfile *packagelockjson.LockFile) map[string]bool {
	registryResolvedMap := make(map[string]bool)

	if lockfile.Packages != nil {
		registryResolvedMap = lockfilePackages(lockfile.Packages)
	}
	if lockfile.Dependencies != nil {
		maps.Copy(registryResolvedMap, lockfileDependencies(lockfile.Dependencies))
	}
	return registryResolvedMap
}

func lockfilePackages(packages map[string]packagelockjson.Package) map[string]bool {
	packagesResolvedMap := make(map[string]bool)
	for namePath, pkg := range packages {
		if namePath == "" {
			continue
		}
		pkgName := pkg.Name
		if pkgName == "" {
			pkgName = packageName(namePath)
		}
		packagesResolvedMap[pkgName] = strings.HasPrefix(pkg.Resolved, npmRegistryURL)
	}
	return packagesResolvedMap
}

func lockfileDependencies(dependencies map[string]packagelockjson.Dependency) map[string]bool {
	resolvedMap := make(map[string]bool)
	resolvedLockfileDependencies(dependencies, resolvedMap)
	return resolvedMap
}

func resolvedLockfileDependencies(dependencies map[string]packagelockjson.Dependency, dependenciesResolvedMap map[string]bool) {
	for name, detail := range dependencies {
		identifier := dependencyName(name, detail.Version)
		if dependenciesResolvedMap[identifier] {
			continue
		}
		dependenciesResolvedMap[identifier] = detail.Resolved != "" && strings.HasPrefix(detail.Resolved, npmRegistryURL)
		if detail.Dependencies != nil {
			resolvedLockfileDependencies(detail.Dependencies, dependenciesResolvedMap)
		}
	}
}

func dependencyName(name string, version string) string {
	prefix := "npm:"
	if strings.HasPrefix(version, prefix) {
		i := strings.LastIndex(version, "@")
		if i < len(prefix)+1 {
			return name
		}
		return version[len(prefix):i]
	}
	return name
}

func packageName(name string) string {
	maybeScope := path.Base(path.Dir(name))
	pkgName := path.Base(name)

	if strings.HasPrefix(maybeScope, "@") {
		pkgName = maybeScope + "/" + pkgName
	}

	return pkgName
}

func npmLockfile(lockfile string, fsys scalibrfs.FS) (*packagelockjson.LockFile, error) {
	data, err := fs.ReadFile(fsys, lockfile)
	if err != nil {
		return nil, err
	}

	parsedLockfile := &packagelockjson.LockFile{}
	if err := json.Unmarshal(data, parsedLockfile); err != nil {
		return nil, err
	}

	if parsedLockfile.Packages == nil && parsedLockfile.Dependencies == nil {
		return nil, fmt.Errorf("lockfile %q is empty", lockfile)
	}

	return parsedLockfile, nil
}

// MapNPMProjectRootsToPackages maps the root-level directories to packages where they were installed from.
// Note that only NPM packages from root/node_modules/../package.json are considered.
// For example, if package @foo/bar was installed from root/node_modules/foo/bar/package.json,
// then the map will contain root as the key and package @foo/bar as the value.
func MapNPMProjectRootsToPackages(packages []*extractor.Package) map[string][]*extractor.Package {
	rootsToPackages := map[string][]*extractor.Package{}
	for _, pkg := range packages {
		if len(pkg.Locations) == 0 || pkg.PURLType != purl.TypeNPM {
			continue
		}

		for _, loc := range pkg.Locations {
			root := npmProjectRootDirectory(loc)
			if root == "" {
				continue
			}
			rootsToPackages[root] = append(rootsToPackages[root], pkg)
			break
		}
	}
	return rootsToPackages
}

func npmProjectRootDirectory(path string) string {
	// Only consider packages from root/node_modules/../package.json.
	if !(filepath.Base(path) == "package.json" && strings.Contains(path, nodeModulesDirectory)) {
		// We are silently dropping packages that are outside of root/node_modules/../package.json.
		return ""
	}

	nodeModulesIndex := strings.Index(filepath.ToSlash(path), "/node_modules/")
	if nodeModulesIndex == -1 {
		return ""
	}

	return path[:nodeModulesIndex]
}
