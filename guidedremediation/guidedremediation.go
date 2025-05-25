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
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"deps.dev/util/resolve"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/guidedremediation/internal/lockfile"
	npmlock "github.com/google/osv-scalibr/guidedremediation/internal/lockfile/npm"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest/maven"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest/npm"
	"github.com/google/osv-scalibr/guidedremediation/internal/remediation"
	"github.com/google/osv-scalibr/guidedremediation/internal/strategy/inplace"
	"github.com/google/osv-scalibr/guidedremediation/internal/strategy/override"
	"github.com/google/osv-scalibr/guidedremediation/internal/strategy/relax"
	"github.com/google/osv-scalibr/guidedremediation/internal/suggest"
	"github.com/google/osv-scalibr/guidedremediation/internal/util"
	"github.com/google/osv-scalibr/guidedremediation/matcher"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
	"github.com/google/osv-scalibr/log"
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

	// If a strategy is specified, try to use it (if it's supported).
	if opts.Strategy != "" {
		// Prefer modifying the manifest over the lockfile, if both are provided.
		// (Though, there are no strategies that work on both)
		if hasManifest && slices.Contains(manifestRW.SupportedStrategies(), opts.Strategy) {
			return doManifestStrategy(context.Background(), opts.Strategy, manifestRW, opts)
		}
		if hasLockfile && slices.Contains(lockfileRW.SupportedStrategies(), opts.Strategy) {
			return doLockfileStrategy(context.Background(), opts.Strategy, lockfileRW, opts)
		}
		return result.Result{}, fmt.Errorf("unsupported strategy: %q", opts.Strategy)
	}

	// No strategy specified, so use the first supported strategy.
	// With manifest strategies taking precedence over lockfile.
	if hasManifest {
		strats := manifestRW.SupportedStrategies()
		if len(strats) > 0 {
			return doManifestStrategy(context.Background(), strats[0], manifestRW, opts)
		}
	} else if hasLockfile {
		strats := lockfileRW.SupportedStrategies()
		if len(strats) > 0 {
			return doLockfileStrategy(context.Background(), strats[0], lockfileRW, opts)
		}
	}

	// This should be unreachable.
	// Supported manifests/lockfiles should have at least one strategy.
	return result.Result{}, errors.New("no supported strategies found")
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

func doManifestStrategy(ctx context.Context, s strategy.Strategy, rw manifest.ReadWriter, opts options.FixVulnsOptions) (result.Result, error) {
	var computePatches func(context.Context, resolve.Client, matcher.VulnerabilityMatcher, *remediation.ResolvedManifest, *options.RemediationOptions) ([]result.Patch, error)
	switch s {
	case strategy.StrategyOverride:
		computePatches = override.ComputePatches
	case strategy.StrategyRelax:
		computePatches = relax.ComputePatches
	default:
		return result.Result{}, fmt.Errorf("unsupported strategy: %q", s)
	}
	m, err := parseManifest(opts.Manifest, rw)
	if err != nil {
		return result.Result{}, err
	}

	res := result.Result{
		Path:      opts.Manifest,
		Strategy:  s,
		Ecosystem: util.DepsDevToOSVEcosystem(rw.System()),
	}

	resolved, err := remediation.ResolveManifest(ctx, opts.ResolveClient, opts.MatcherClient, m, &opts.RemediationOptions)
	if err != nil {
		return result.Result{}, fmt.Errorf("failed resolving manifest: %w", err)
	}

	res.Errors = computeResolveErrors(resolved.Graph)

	writeLockfile := false
	if opts.Lockfile != "" {
		if isLockfileForManifest(opts.Manifest, opts.Lockfile) {
			writeLockfile = true
			err := computeRelockPatches(ctx, &res, resolved, opts)
			if err != nil {
				log.Errorf("failed computing vulnerabilies fixed by relock: %v", err)
				// just ignore the lockfile and continue.
			}
		} else {
			log.Warnf("ignoring lockfile %q because it is not for manifest %q", opts.Lockfile, opts.Manifest)
		}
	}

	allPatches, err := computePatches(ctx, opts.ResolveClient, opts.MatcherClient, resolved, &opts.RemediationOptions)
	if err != nil {
		return result.Result{}, fmt.Errorf("failed computing patches: %w", err)
	}

	res.Vulnerabilities = append(res.Vulnerabilities, computeVulnsResult(resolved, allPatches)...)
	res.Patches = append(res.Patches, choosePatches(allPatches, opts.MaxUpgrades, opts.NoIntroduce, false)...)
	if err := writeManifestPatches(opts.Manifest, m, res.Patches, rw); err != nil {
		return res, err
	}

	if writeLockfile {
		err := writeLockfileFromManifest(ctx, opts.Manifest)
		if err != nil {
			log.Errorf("failed writing lockfile from manifest: %v", err)
		}
	}

	return res, nil
}

func doLockfileStrategy(ctx context.Context, s strategy.Strategy, rw lockfile.ReadWriter, opts options.FixVulnsOptions) (result.Result, error) {
	if s != strategy.StrategyInPlace {
		return result.Result{}, fmt.Errorf("unsupported strategy: %q", s)
	}
	g, err := parseLockfile(opts.Lockfile, rw)
	if err != nil {
		return result.Result{}, err
	}

	res := result.Result{
		Path:      opts.Lockfile,
		Strategy:  s,
		Ecosystem: util.DepsDevToOSVEcosystem(rw.System()),
	}

	resolved, err := remediation.ResolveGraphVulns(ctx, opts.ResolveClient, opts.MatcherClient, g, nil, &opts.RemediationOptions)
	if err != nil {
		return result.Result{}, fmt.Errorf("failed resolving lockfile vulnerabilities: %w", err)
	}
	res.Errors = computeResolveErrors(resolved.Graph)
	allPatches, err := inplace.ComputePatches(ctx, opts.ResolveClient, resolved, &opts.RemediationOptions)
	if err != nil {
		return result.Result{}, fmt.Errorf("failed computing patches: %w", err)
	}
	res.Vulnerabilities = computeVulnsResultsLockfile(resolved, allPatches)
	res.Patches = choosePatches(allPatches, opts.MaxUpgrades, opts.NoIntroduce, true)
	err = writeLockfilePatches(opts.Lockfile, res.Patches, rw)
	return res, err
}

// computeVulnsResult computes the vulnerabilities that were found in the resolved manifest,
// where vulnerabilities are unique by ID only, and are actionable only if it can be fixed in all affected packages.
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
			vuln.Packages = append(vuln.Packages, result.Package{
				Name:    vk.Name,
				Version: vk.Version,
				PURL:    util.VKToPURL(vk).String(),
			})
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

// computeVulnsResultsLockfile computes the vulnerabilities that were found in the resolved lockfile,
// where vulnerabilities are unique by ID AND affected package + version.
// e.g. CVE-123-456 affecting foo@1.0.0 is different from CVE-123-456 affecting foo@2.0.0.
// Vulnerabilities are actionable if it can be fixed in all instances of the affected package version.
// (in the case of npm, where a version of a package can be installed in multiple places in the project)
func computeVulnsResultsLockfile(resolved remediation.ResolvedGraph, allPatches []result.Patch) []result.Vuln {
	type vuln struct {
		id         string
		pkgName    string
		pkgVersion string
	}
	fixableVulns := make(map[vuln]struct{})
	for _, p := range allPatches {
		for _, v := range p.Fixed {
			for _, pkg := range v.Packages {
				fixableVulns[vuln{v.ID, pkg.Name, pkg.Version}] = struct{}{}
			}
		}
	}

	var vulns []result.Vuln
	for _, v := range resolved.Vulns {
		vks := make(map[resolve.VersionKey]struct{})
		for _, sg := range v.Subgraphs {
			vks[sg.Nodes[sg.Dependency].Version] = struct{}{}
		}
		for vk := range vks {
			_, fixable := fixableVulns[vuln{v.OSV.ID, vk.Name, vk.Version}]
			vulns = append(vulns, result.Vuln{
				ID:           v.OSV.ID,
				Unactionable: !fixable,
				Packages: []result.Package{{
					Name:    vk.Name,
					Version: vk.Version,
				}},
			})
		}
	}
	slices.SortFunc(vulns, func(a, b result.Vuln) int {
		return cmp.Or(
			strings.Compare(a.ID, b.ID),
			strings.Compare(a.Packages[0].Name, b.Packages[0].Name),
			strings.Compare(a.Packages[0].Version, b.Packages[0].Version),
		)
	})
	return vulns
}

// choosePatches chooses up to maxUpgrades compatible patches to apply.
// If maxUpgrades <= 0, chooses as many as possible.
// If lockfileVulns is true, vulns are considered unique by ID AND affected package + version,
// so a patch may be chosen that fixes one occurrence of a vulnerability, but not all.
// If lockfileVulns is false, vulns are considered unique by ID only,
// so patches must fix all occurrences of a vulnerability to be chosen.
func choosePatches(allPatches []result.Patch, maxUpgrades int, noIntroduce bool, lockfileVulns bool) []result.Patch {
	var patches []result.Patch
	pkgChanges := make(map[result.Package]struct{}) // dependencies we've already applied a patch to
	type vulnIdentifier struct {
		id         string
		pkgName    string
		pkgVersion string
	}
	fixedVulns := make(map[vulnIdentifier]struct{}) // vulns that have already been fixed by a patch
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
			identifier := vulnIdentifier{id: v.ID}
			if lockfileVulns {
				identifier.pkgName = patch.PackageUpdates[0].Name
				identifier.pkgVersion = patch.PackageUpdates[0].VersionFrom
			}
			_, ok := fixedVulns[identifier]
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
			identifier := vulnIdentifier{id: v.ID}
			if lockfileVulns {
				identifier.pkgName = patch.PackageUpdates[0].Name
				identifier.pkgVersion = patch.PackageUpdates[0].VersionFrom
			}
			fixedVulns[identifier] = struct{}{}
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
					PURL:    util.VKToPURL(n.Version).String(),
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

// computeRelockPatches computes the vulnerabilities that were fixed by just relocking the manifest.
// Vulns present in the lockfile only are added to the result's vulns,
// and a patch upgraded packages is added to the result's patches.
func computeRelockPatches(ctx context.Context, res *result.Result, resolvedManif *remediation.ResolvedManifest, opts options.FixVulnsOptions) error {
	lockfileRW, err := readWriterForLockfile(opts.Lockfile)
	if err != nil {
		return err
	}

	g, err := parseLockfile(opts.Lockfile, lockfileRW)
	if err != nil {
		return err
	}
	resolvedLockf, err := remediation.ResolveGraphVulns(ctx, opts.ResolveClient, opts.MatcherClient, g, nil, &opts.RemediationOptions)
	if err != nil {
		return err
	}

	manifestVulns := make(map[string]struct{})
	for _, v := range resolvedManif.Vulns {
		manifestVulns[v.OSV.ID] = struct{}{}
	}

	var vulns []result.Vuln
	for _, v := range resolvedLockf.Vulns {
		if _, ok := manifestVulns[v.OSV.ID]; !ok {
			vuln := result.Vuln{ID: v.OSV.ID, Unactionable: false}
			for _, sg := range v.Subgraphs {
				n := resolvedLockf.Graph.Nodes[sg.Dependency]
				vuln.Packages = append(vuln.Packages, result.Package{Name: n.Version.Name, Version: n.Version.Version})
			}
			vulns = append(vulns, vuln)
		}
	}

	slices.SortFunc(vulns, func(a, b result.Vuln) int { return strings.Compare(a.ID, b.ID) })
	res.Vulnerabilities = append(res.Vulnerabilities, vulns...)
	res.Patches = append(res.Patches, result.Patch{Fixed: vulns})

	return nil
}

func writeLockfileFromManifest(ctx context.Context, manifestPath string) error {
	base := filepath.Base(manifestPath)
	if base != "package.json" {
		return fmt.Errorf("unsupported manifest: %q", base)
	}

	// shell out to npm to write the package-lock.json file.
	dir := filepath.Dir(manifestPath)
	npmPath, err := exec.LookPath("npm")
	if err != nil {
		return fmt.Errorf("cannot find npm executable: %w", err)
	}

	// Must remove preexisting package-lock.json and node_modules directory for a clean install.
	// Use RemoveAll to avoid errors if the files doesn't exist.
	if err := os.RemoveAll(filepath.Join(dir, "package-lock.json")); err != nil {
		return fmt.Errorf("failed removing old package-lock.json/: %w", err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "node_modules")); err != nil {
		return fmt.Errorf("failed removing old node_modules/: %w", err)
	}

	cmd := exec.CommandContext(ctx, npmPath, "install", "--package-lock-only")
	cmd.Dir = dir
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err == nil {
		// succeeded on first try
		return nil
	}

	// Guided remediation does not currently support peer dependencies.
	// Try with `--legacy-peer-deps` in case the previous install errored from peer dependencies.
	log.Warnf("npm install failed. Trying again with `--legacy-peer-deps`")
	cmd = exec.CommandContext(ctx, npmPath, "install", "--package-lock-only", "--legacy-peer-deps")
	cmd.Dir = dir
	cmdOut := &strings.Builder{}
	cmd.Stdout = cmdOut
	cmd.Stderr = cmdOut
	if err := cmd.Run(); err != nil {
		log.Infof("npm install output:\n%s", cmdOut.String())
		return fmt.Errorf("npm install failed: %w", err)
	}

	return nil
}

func readWriterForManifest(manifestPath string, registry string) (manifest.ReadWriter, error) {
	baseName := filepath.Base(manifestPath)
	switch strings.ToLower(baseName) {
	case "pom.xml":
		return maven.GetReadWriter(registry, "")
	case "package.json":
		return npm.GetReadWriter(registry)
	}
	return nil, fmt.Errorf("unsupported manifest: %q", baseName)
}

func readWriterForLockfile(lockfilePath string) (lockfile.ReadWriter, error) {
	baseName := filepath.Base(lockfilePath)
	switch strings.ToLower(baseName) {
	case "package-lock.json":
		return npmlock.GetReadWriter()
	}
	return nil, fmt.Errorf("unsupported lockfile: %q", baseName)
}

// isLockfileForManifest returns true if the lockfile is for the manifest.
// This is a heuristic that works for npm, but not for other ecosystems.
func isLockfileForManifest(manifestPath, lockfilePath string) bool {
	manifestDir := filepath.Dir(manifestPath)
	manifestBaseName := filepath.Base(manifestPath)
	lockfileDir := filepath.Dir(lockfilePath)
	lockfileBaseName := filepath.Base(lockfilePath)

	// currently only npm has a lockfile and manifest.
	return manifestBaseName == "package.json" && lockfileBaseName == "package-lock.json" && manifestDir == lockfileDir
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

func parseLockfile(path string, rw lockfile.ReadWriter) (*resolve.Graph, error) {
	fsys, path, err := fsAndPath(path)
	if err != nil {
		return nil, err
	}

	g, err := rw.Read(path, fsys)
	if err != nil {
		return nil, fmt.Errorf("error reading lockfile: %w", err)
	}
	return g, nil
}

func writeManifestPatches(path string, m manifest.Manifest, patches []result.Patch, rw manifest.ReadWriter) error {
	fsys, _, err := fsAndPath(path)
	if err != nil {
		return err
	}

	return rw.Write(m, fsys, patches, path)
}

func writeLockfilePatches(path string, patches []result.Patch, rw lockfile.ReadWriter) error {
	fsys, relPath, err := fsAndPath(path)
	if err != nil {
		return err
	}

	return rw.Write(relPath, fsys, patches, path)
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
