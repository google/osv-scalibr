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

// Package guidedremediation provides vulnerability fixing through dependency
// updates in manifest and lockfiles.
package guidedremediation

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	golog "log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"deps.dev/util/resolve"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/guidedremediation/internal/lockfile"
	npmlock "github.com/google/osv-scalibr/guidedremediation/internal/lockfile/npm"
	pythonlock "github.com/google/osv-scalibr/guidedremediation/internal/lockfile/python"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest/maven"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest/npm"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest/python"
	"github.com/google/osv-scalibr/guidedremediation/internal/parser"
	"github.com/google/osv-scalibr/guidedremediation/internal/remediation"
	"github.com/google/osv-scalibr/guidedremediation/internal/resolution"
	"github.com/google/osv-scalibr/guidedremediation/internal/strategy/common"
	"github.com/google/osv-scalibr/guidedremediation/internal/strategy/inplace"
	"github.com/google/osv-scalibr/guidedremediation/internal/strategy/override"
	"github.com/google/osv-scalibr/guidedremediation/internal/strategy/relax"
	"github.com/google/osv-scalibr/guidedremediation/internal/suggest"
	"github.com/google/osv-scalibr/guidedremediation/internal/tui/components"
	"github.com/google/osv-scalibr/guidedremediation/internal/tui/model"
	"github.com/google/osv-scalibr/guidedremediation/internal/util"
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
		hasManifest = opts.Manifest != ""
		hasLockfile = opts.Lockfile != ""
		manifestRW  manifest.ReadWriter
		lockfileRW  lockfile.ReadWriter
	)
	if !hasManifest && !hasLockfile {
		return result.Result{}, errors.New("no manifest or lockfile provided")
	}
	if opts.VulnEnricher == nil || !strings.HasPrefix(opts.VulnEnricher.Name(), "vulnmatch/") {
		return result.Result{}, errors.New("vulnmatch/ enricher is required for guided remediation")
	}

	if hasManifest {
		var err error
		manifestRW, err = readWriterForManifest(opts.Manifest, opts.MavenClient)
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

// VulnDetailsRenderer provides a Render function for the markdown details of a vulnerability.
type VulnDetailsRenderer components.DetailsRenderer

// FixVulnsInteractive launches the guided remediation interactive TUI.
// detailsRenderer is used to render the markdown details of vulnerabilities, if nil, a fallback renderer is used.
func FixVulnsInteractive(opts options.FixVulnsOptions, detailsRenderer VulnDetailsRenderer) error {
	if opts.VulnEnricher == nil || !strings.HasPrefix(opts.VulnEnricher.Name(), "vulnmatch/") {
		return errors.New("vulnmatch/ enricher is required for guided remediation")
	}
	// Explicitly specifying vulns by cli flag doesn't really make sense in interactive mode.
	opts.ExplicitVulns = []string{}
	var manifestRW manifest.ReadWriter
	var lockfileRW lockfile.ReadWriter
	if opts.Manifest != "" {
		var err error
		manifestRW, err = readWriterForManifest(opts.Manifest, opts.MavenClient)
		if err != nil {
			return err
		}
		if !slices.Contains(manifestRW.SupportedStrategies(), strategy.StrategyRelax) {
			return errors.New("interactive mode only supports relax strategy for manifests")
		}
	}
	if opts.Lockfile != "" {
		var err error
		lockfileRW, err = readWriterForLockfile(opts.Lockfile)
		if err != nil {
			return err
		}
		if !slices.Contains(lockfileRW.SupportedStrategies(), strategy.StrategyInPlace) {
			return errors.New("interactive mode only supports inplace strategy for lockfiles")
		}
	}

	var m tea.Model
	var err error
	m, err = model.NewModel(manifestRW, lockfileRW, opts, detailsRenderer)
	if err != nil {
		return err
	}
	p := tea.NewProgram(m, tea.WithAltScreen())

	// Disable scalibr logging to avoid polluting the terminal.
	golog.SetOutput(io.Discard)
	m, err = p.Run()
	golog.SetOutput(os.Stderr)
	if err != nil {
		return err
	}

	md, ok := m.(model.Model)
	if !ok {
		log.Warnf("tui exited in unexpected state: %v", m)
		return nil
	}
	return md.Error()
}

// Update updates the dependencies to the latest version based on the UpdateOptions provided.
// Update overwrites the manifest on disk with the updated dependencies.
func Update(opts options.UpdateOptions) (result.Result, error) {
	var (
		hasManifest = (opts.Manifest != "")
		manifestRW  manifest.ReadWriter
	)
	if !hasManifest {
		return result.Result{}, errors.New("no manifest provided")
	}

	var err error
	manifestRW, err = readWriterForManifest(opts.Manifest, opts.MavenClient)
	if err != nil {
		return result.Result{}, err
	}

	mf, err := parser.ParseManifest(opts.Manifest, manifestRW)
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

	err = parser.WriteManifestPatches(opts.Manifest, mf, []result.Patch{patch}, manifestRW)

	return result.Result{
		Path:      opts.Manifest,
		Ecosystem: util.DepsDevToOSVEcosystem(manifestRW.System()),
		Patches:   []result.Patch{patch},
	}, err
}

func doManifestStrategy(ctx context.Context, s strategy.Strategy, rw manifest.ReadWriter, opts options.FixVulnsOptions) (result.Result, error) {
	var computePatches func(context.Context, resolve.Client, enricher.Enricher, *remediation.ResolvedManifest, *options.RemediationOptions) (common.PatchResult, error)
	switch s {
	case strategy.StrategyOverride:
		computePatches = override.ComputePatches
	case strategy.StrategyRelax:
		computePatches = relax.ComputePatches
	case strategy.StrategyInPlace:
		fallthrough
	default:
		return result.Result{}, fmt.Errorf("unsupported strategy: %q", s)
	}
	m, err := parser.ParseManifest(opts.Manifest, rw)
	if err != nil {
		return result.Result{}, err
	}

	res := result.Result{
		Path:      opts.Manifest,
		Strategy:  s,
		Ecosystem: util.DepsDevToOSVEcosystem(rw.System()),
	}

	if opts.DepCachePopulator != nil {
		opts.DepCachePopulator.PopulateCache(ctx, opts.ResolveClient, m.Requirements(), opts.Manifest)
	}

	resolved, err := remediation.ResolveManifest(ctx, opts.ResolveClient, opts.VulnEnricher, m, &opts.RemediationOptions)
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

	allPatchResults, err := computePatches(ctx, opts.ResolveClient, opts.VulnEnricher, resolved, &opts.RemediationOptions)
	if err != nil {
		return result.Result{}, fmt.Errorf("failed computing patches: %w", err)
	}
	allPatches := allPatchResults.Patches

	res.Vulnerabilities = append(res.Vulnerabilities, computeVulnsResult(resolved, allPatches)...)
	res.Patches = append(res.Patches, choosePatches(allPatches, opts.MaxUpgrades, opts.NoIntroduce, false)...)
	if m.System() == resolve.Maven && opts.NoMavenNewDepMgmt {
		res.Patches = filterMavenPatches(res.Patches, m.EcosystemSpecific())
	}
	if err := parser.WriteManifestPatches(opts.Manifest, m, res.Patches, rw); err != nil {
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
	g, err := parser.ParseLockfile(opts.Lockfile, rw)
	if err != nil {
		return result.Result{}, err
	}

	res := result.Result{
		Path:      opts.Lockfile,
		Strategy:  s,
		Ecosystem: util.DepsDevToOSVEcosystem(rw.System()),
	}

	resolved, err := remediation.ResolveGraphVulns(ctx, opts.ResolveClient, opts.VulnEnricher, g, nil, &opts.RemediationOptions)
	if err != nil {
		return result.Result{}, fmt.Errorf("failed resolving lockfile vulnerabilities: %w", err)
	}
	res.Errors = computeResolveErrors(resolved.Graph)
	allPatches, err := inplace.ComputePatches(ctx, opts.ResolveClient, resolved, &opts.RemediationOptions)
	if err != nil {
		return result.Result{}, fmt.Errorf("failed computing patches: %w", err)
	}
	res.Vulnerabilities = computeVulnsResultsLockfile(resolved, allPatches, opts.RemediationOptions)
	res.Patches = choosePatches(allPatches, opts.MaxUpgrades, opts.NoIntroduce, true)
	err = parser.WriteLockfilePatches(opts.Lockfile, res.Patches, rw)
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
		_, fixable := fixableVulns[v.OSV.Id]
		vuln := result.Vuln{
			ID:           v.OSV.Id,
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

// computeVulnsResultsLockfile computes the vulnerabilities that were found in the resolved lockfile,
// where vulnerabilities are unique by ID AND affected package + version.
// e.g. CVE-123-456 affecting foo@1.0.0 is different from CVE-123-456 affecting foo@2.0.0.
// Vulnerabilities are actionable if it can be fixed in all instances of the affected package version.
// (in the case of npm, where a version of a package can be installed in multiple places in the project)
func computeVulnsResultsLockfile(resolved remediation.ResolvedGraph, allPatches []result.Patch, opts options.RemediationOptions) []result.Vuln {
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
			// Check if the split vulnerability should've been filtered out.
			vuln := resolution.Vulnerability{
				OSV:       v.OSV,
				Subgraphs: []*resolution.DependencySubgraph{sg},
				DevOnly:   sg.IsDevOnly(nil),
			}
			if remediation.MatchVuln(opts, vuln) {
				vks[sg.Nodes[sg.Dependency].Version] = struct{}{}
			}
		}
		for vk := range vks {
			_, fixable := fixableVulns[vuln{v.OSV.Id, vk.Name, vk.Version}]
			vulns = append(vulns, result.Vuln{
				ID:           v.OSV.Id,
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

// filterMavenPatches filters out Maven patches that are not allowed.
func filterMavenPatches(allPatches []result.Patch, ecosystemSpecific any) []result.Patch {
	specific, ok := ecosystemSpecific.(maven.ManifestSpecific)
	if !ok {
		return allPatches
	}
	for i := range allPatches {
		allPatches[i].PackageUpdates = slices.DeleteFunc(allPatches[i].PackageUpdates, func(update result.PackageUpdate) bool {
			origDep := maven.OriginalDependency(update, specific.LocalRequirements)
			// An empty name indicates the original dependency is not in the base project.
			// If so, delete the patch if the new dependency management is not allowed.
			return origDep.Name() == ":"
		})
	}
	// Delete the patch if there are no package updates.
	return slices.DeleteFunc(allPatches, func(patch result.Patch) bool {
		return len(patch.PackageUpdates) == 0
	})
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

	g, err := parser.ParseLockfile(opts.Lockfile, lockfileRW)
	if err != nil {
		return err
	}
	resolvedLockf, err := remediation.ResolveGraphVulns(ctx, opts.ResolveClient, opts.VulnEnricher, g, nil, &opts.RemediationOptions)
	if err != nil {
		return err
	}

	manifestVulns := make(map[string]struct{})
	for _, v := range resolvedManif.Vulns {
		manifestVulns[v.OSV.Id] = struct{}{}
	}

	var vulns []result.Vuln
	for _, v := range resolvedLockf.Vulns {
		if _, ok := manifestVulns[v.OSV.Id]; !ok {
			vuln := result.Vuln{ID: v.OSV.Id, Unactionable: false}
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
	switch base {
	case "package.json":
		return writeNpmLockfile(ctx, manifestPath)
	case "requirements.in":
		return writePythonLockfile(ctx, manifestPath, "pip-compile", "requirements.txt", "--generate-hashes", "requirements.in")
	case "pyproject.toml":
		return writePythonLockfile(ctx, manifestPath, "poetry", "poetry.lock", "lock")
	case "Pipfile":
		return writePythonLockfile(ctx, manifestPath, "pipenv", "Pipfile.lock", "lock")
	default:
		return fmt.Errorf("unsupported manifest type: %s", base)
	}
}

func writeNpmLockfile(ctx context.Context, path string) error {
	// shell out to npm to write the package-lock.json file.
	dir := filepath.Dir(path)
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

	cmd := exec.CommandContext(ctx, npmPath, "install", "--package-lock-only", "--ignore-scripts")
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
	cmd = exec.CommandContext(ctx, npmPath, "install", "--package-lock-only", "--legacy-peer-deps", "--ignore-scripts")
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

// writePythonLockfile executes a command-line tool to generate or update a lockfile.
func writePythonLockfile(ctx context.Context, path, executable, lockfileName string, args ...string) error {
	dir := filepath.Dir(path)
	execPath, err := exec.LookPath(executable)
	if err != nil {
		return fmt.Errorf("cannot find %s executable: %w", executable, err)
	}

	log.Infof("Running %s to regenerate %s", executable, lockfileName)
	cmd := exec.CommandContext(ctx, execPath, args...)
	cmd.Dir = dir
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

// readWriterForManifest returns the manifest read/write interface for the given manifest path.
// mavenClient is used to read/write Maven manifests, and may be nil for other ecosystems.
func readWriterForManifest(manifestPath string, mavenClient *datasource.MavenRegistryAPIClient) (manifest.ReadWriter, error) {
	baseName := filepath.Base(manifestPath)
	switch strings.ToLower(baseName) {
	case "pom.xml":
		if mavenClient == nil {
			return nil, errors.New("a maven client must be provided for pom.xml")
		}
		return maven.GetReadWriter(mavenClient)
	case "package.json":
		return npm.GetReadWriter()
	case "requirements.in", "requirements.txt":
		return python.GetRequirementsReadWriter()
	case "pyproject.toml":
		return python.GetPoetryReadWriter()
	case "pipfile":
		return python.GetPipfileReadWriter()
	}
	return nil, fmt.Errorf("unsupported manifest: %q", baseName)
}

// readWriterForLockfile returns the lockfile read/write interface for the given lockfile path.
func readWriterForLockfile(lockfilePath string) (lockfile.ReadWriter, error) {
	baseName := filepath.Base(lockfilePath)
	switch strings.ToLower(baseName) {
	case "package-lock.json":
		return npmlock.GetReadWriter()
	case "requirements.txt":
		return pythonlock.GetReadWriter()
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

	if manifestDir != lockfileDir {
		return false
	}
	if manifestBaseName == "requirements.in" {
		return lockfileBaseName == "requirements.txt"
	}
	if manifestBaseName == "pyproject.toml" {
		return lockfileBaseName == "poetry.lock"
	}
	if manifestBaseName == "Pipfile" {
		return lockfileBaseName == "Pipfile.lock"
	}
	return manifestBaseName == "package.json" && lockfileBaseName == "package-lock.json"
}
