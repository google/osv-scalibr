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

// Package guidedremediation provides vulnerability fixing through dependency
// updates in manifest and lockfiles.
package guidedremediation

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"deps.dev/util/resolve"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/guidedremediation/internal/lockfile"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest/maven"
	"github.com/google/osv-scalibr/guidedremediation/internal/remediation"
	"github.com/google/osv-scalibr/guidedremediation/internal/strategy/override"
	"github.com/google/osv-scalibr/guidedremediation/internal/suggest"
	"github.com/google/osv-scalibr/guidedremediation/internal/util"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
)

// FixVulns remediates vulnerabilities in the manifest/lockfile using a remediation strategy,
// which are specified in the RemediationOptions.
// FixVulns will overwrite the manifest/lockfile(s) on disk with the dependencies
// patched to remove vulnerabilities. It also returns a Result describing the changes made.
func FixVulns(opts options.FixVulnsOptions) (result.Result, error) {
	var (
		hasManifest bool = (opts.Manifest != "")
		hasLockfile bool = (opts.Lockfile != "")
		manifestRW  manifest.ReadWriter
		lockfileRW  lockfile.ReadWriter
	)
	if !hasManifest && !hasLockfile {
		return result.Result{}, errors.New("no manifest or lockfile provided")
	}

	if hasManifest {
		var err error
		manifestRW, err = readWriterForManifest(opts.Manifest, opts.DefaultRepository)
		if err != nil {
			return result.Result{}, err
		}
	}
	if hasLockfile {
		var err error
		lockfileRW, err = readWriterForLockfile(opts.Lockfile)
		if err != nil {
			return result.Result{}, err
		}
	}

	stgy := opts.Strategy
	// If strategy is unset, choose a supported strategy from the manifest/lockfile
	// Preferring to operate on the manifest rather than the lockfile.
	if stgy == "" {
		var strats []strategy.Strategy
		if hasManifest {
			strats = manifestRW.SupportedStrategies()
		}
		if hasLockfile {
			strats = append(strats, lockfileRW.SupportedStrategies()...)
		}
		if len(strats) == 0 {
			// This should be unreachable.
			// Supported manifests/lockfiles should have at least one strategy.
			return result.Result{}, errors.New("no supported strategies")
		}
		stgy = strats[0]
	}

	switch stgy {
	case strategy.StrategyOverride:
		return doOverride(context.Background(), manifestRW, opts)
	}

	return result.Result{}, fmt.Errorf("unsupported strategy: %q", stgy)
}

// Update updates the dependencies to the latest version based on the UpdateOptions provided.
// Update overwrites the manifest on disk with the updated dependencies.
func Update(opts options.UpdateOptions) (result.Result, error) {
	var (
		hasManifest bool = (opts.Manifest != "")
		manifestRW  manifest.ReadWriter
	)
	if !hasManifest {
		return result.Result{}, errors.New("no manifest provided")
	}

	var err error
	manifestRW, err = readWriterForManifest(opts.Manifest, opts.DefaultRepository)
	if err != nil {
		return result.Result{}, err
	}

	mf, err := parseManifest(opts.Manifest, manifestRW)
	if err != nil {
		return result.Result{}, err
	}

	suggester, err := suggest.NewSuggester(manifestRW.System())
	if err != nil {
		return result.Result{}, err
	}
	patch, err := suggester.Suggest(context.Background(), mf, opts)
	if err != nil {
		return result.Result{}, err
	}

	err = writeManifestPatches(opts.Manifest, mf, []result.Patch{patch}, manifestRW)

	return result.Result{
		Path:      opts.Manifest,
		Ecosystem: util.DepsDevToOSVEcosystem(manifestRW.System()),
		Patches:   []result.Patch{patch},
	}, err
}

func doOverride(ctx context.Context, rw manifest.ReadWriter, opts options.FixVulnsOptions) (result.Result, error) {
	m, err := parseManifest(opts.Manifest, rw)
	if err != nil {
		return result.Result{}, err
	}

	res := result.Result{
		Path:      opts.Manifest,
		Strategy:  strategy.StrategyOverride,
		Ecosystem: util.DepsDevToOSVEcosystem(rw.System()),
	}

	resolved, err := remediation.ResolveManifest(ctx, opts.ResolveClient, opts.MatcherClient, m, &opts.RemediationOptions)
	if err != nil {
		return result.Result{}, fmt.Errorf("failed resolving manifest: %w", err)
	}

	res.Errors = computeResolveErrors(resolved.Graph)
	allPatches, err := override.ComputePatches(ctx, opts.ResolveClient, opts.MatcherClient, resolved, &opts.RemediationOptions)
	if err != nil {
		return result.Result{}, fmt.Errorf("failed computing patches: %w", err)
	}

	res.Vulnerabilities = computeVulnsResult(resolved, allPatches)
	res.Patches = choosePatches(allPatches, opts.MaxUpgrades, opts.NoIntroduce)
	err = writeManifestPatches(opts.Manifest, m, res.Patches, rw)

	return res, err
}

func computeVulnsResult(resolved *remediation.ResolvedManifest, allPatches []result.Patch) []result.Vuln {
	fixableVulns := make(map[string]struct{})
	for _, p := range allPatches {
		for _, v := range p.Fixed {
			fixableVulns[v.ID] = struct{}{}
		}
	}
	vulns := make([]result.Vuln, 0, len(resolved.Vulns))
	for _, v := range resolved.Vulns {
		_, fixable := fixableVulns[v.OSV.ID]
		vuln := result.Vuln{
			ID:           v.OSV.ID,
			Unactionable: !fixable,
			Packages:     make([]result.Package, 0, len(v.Subgraphs)),
		}
		for _, sg := range v.Subgraphs {
			vk := sg.Nodes[sg.Dependency].Version
			vuln.Packages = append(vuln.Packages, result.Package{Name: vk.Name, Version: vk.Version})
		}
		// Sort and remove any possible duplicate packages.
		cmpFn := func(a, b result.Package) int {
			if c := strings.Compare(a.Name, b.Name); c != 0 {
				return c
			}
			return strings.Compare(a.Version, b.Version)
		}
		slices.SortFunc(vuln.Packages, cmpFn)
		vuln.Packages = slices.CompactFunc(vuln.Packages, func(a, b result.Package) bool { return cmpFn(a, b) == 0 })
		vulns = append(vulns, vuln)
	}
	slices.SortFunc(vulns, func(a, b result.Vuln) int { return strings.Compare(a.ID, b.ID) })
	return vulns
}

// choosePatches chooses up to maxUpgrades compatible patches to apply.
// If maxUpgrades <= 0, chooses as many as possible.
func choosePatches(allPatches []result.Patch, maxUpgrades int, noIntroduce bool) []result.Patch {
	var patches []result.Patch
	pkgChanges := make(map[result.Package]struct{}) // dependencies we've already applied a patch to
	fixedVulns := make(map[string]struct{})         // vulns that have already been fixed by a patch
	for _, patch := range allPatches {
		// If this patch is incompatible with existing patches, skip adding it to the patch list.

		// A patch is incompatible if any of its changed packages have already been changed by an existing patch.
		if slices.ContainsFunc(patch.PackageUpdates, func(p result.PackageUpdate) bool {
			_, ok := pkgChanges[result.Package{Name: p.Name, Version: p.VersionFrom}]
			return ok
		}) {
			continue
		}
		// A patch is also incompatible if any fixed vulnerability has already been fixed by another patch.
		// This would happen if updating the version of one package has a side effect of also updating or removing one of its vulnerable dependencies.
		// e.g. We have {foo@1 -> bar@1}, and two possible patches [foo@3, bar@2].
		// Patching foo@3 makes {foo@3 -> bar@3}, which also fixes the vulnerability in bar.
		// Applying both patches would force {foo@3 -> bar@2}, which is less desirable.
		if slices.ContainsFunc(patch.Fixed, func(v result.Vuln) bool {
			_, ok := fixedVulns[v.ID]
			return ok
		}) {
			continue
		}

		if noIntroduce && len(patch.Introduced) > 0 {
			continue
		}

		patches = append(patches, patch)
		for _, pkg := range patch.PackageUpdates {
			pkgChanges[result.Package{Name: pkg.Name, Version: pkg.VersionFrom}] = struct{}{}
		}
		for _, v := range patch.Fixed {
			fixedVulns[v.ID] = struct{}{}
		}
		maxUpgrades--
		if maxUpgrades == 0 {
			break
		}
	}
	return patches
}

func computeResolveErrors(g *resolve.Graph) []result.ResolveError {
	var errs []result.ResolveError
	for _, n := range g.Nodes {
		for _, e := range n.Errors {
			errs = append(errs, result.ResolveError{
				Package: result.Package{
					Name:    n.Version.Name,
					Version: n.Version.Version,
				},
				Requirement: result.Package{
					Name:    e.Req.Name,
					Version: e.Req.Version,
				},
				Error: e.Error,
			})
		}
	}

	return errs
}

func readWriterForManifest(manifestPath string, registry string) (manifest.ReadWriter, error) {
	baseName := filepath.Base(manifestPath)
	switch strings.ToLower(baseName) {
	case "pom.xml":
		return maven.GetReadWriter(registry)
		// TODO(#454): package.json when relax strategy is migrated.
	}
	return nil, fmt.Errorf("unsupported manifest: %q", baseName)
}

//nolint:unparam // TODO(#454): implement pending
func readWriterForLockfile(lockfilePath string) (lockfile.ReadWriter, error) {
	baseName := filepath.Base(lockfilePath)
	// TODO(#454): package-lock.json when in-place strategy is migrated.
	// switch strings.ToLower(baseName) {
	// }
	return nil, fmt.Errorf("unsupported lockfile: %q", baseName)
}

func parseManifest(path string, rw manifest.ReadWriter) (manifest.Manifest, error) {
	fsys, path, err := fsAndPath(path)
	if err != nil {
		return nil, err
	}

	m, err := rw.Read(path, fsys)
	if err != nil {
		return nil, fmt.Errorf("error reading manifest: %w", err)
	}
	return m, nil
}

func writeManifestPatches(path string, m manifest.Manifest, patches []result.Patch, rw manifest.ReadWriter) error {
	fsys, _, err := fsAndPath(path)
	if err != nil {
		return err
	}

	return rw.Write(m, fsys, patches, path)
}

func fsAndPath(path string) (scalibrfs.FS, string, error) {
	// We need a DirFS that can potentially access files in parent directories from the file.
	// But you cannot escape the base directory of dirfs.
	// e.g. "pkg/core/pom.xml" may have a parent at "pkg/parent/pom.xml",
	// if we had fsys := scalibrfs.DirFS("pkg/core"), we can't do fsys.Open("../parent/pom.xml")
	//
	// Since we don't know ahead of time which files might be needed,
	// we must use the system root as the directory.

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, "", err
	}

	// Get the path relative to the root (i.e. without the leading '/')
	// On Windows, we need the path relative to the drive letter,
	// which also means we can't open files across drives.
	root := filepath.VolumeName(absPath) + "/"
	relPath, err := filepath.Rel(root, absPath)
	if err != nil {
		return nil, "", err
	}
	relPath = filepath.ToSlash(relPath)

	return scalibrfs.DirFS(root), relPath, nil
}
