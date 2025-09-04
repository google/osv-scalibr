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

package model

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"deps.dev/util/resolve"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/internal/parser"
	"github.com/google/osv-scalibr/guidedremediation/internal/remediation"
	"github.com/google/osv-scalibr/guidedremediation/internal/resolution"
	"github.com/google/osv-scalibr/guidedremediation/internal/strategy/common"
	"github.com/google/osv-scalibr/guidedremediation/internal/strategy/relax"
	"github.com/google/osv-scalibr/guidedremediation/internal/tui/components"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/result"
)

type stateRelockResult struct {
	currRes      *remediation.ResolvedManifest // In-progress relock result, with user-selected patches applied
	currErrs     []result.ResolveError         // In-progress relock errors
	patches      common.PatchResult            // current possible patches applicable to currRes
	patchesDone  bool                          // whether the patches has finished being computed
	numUnfixable int                           // count of unfixable vulns, for rendering

	spinner         spinner.Model
	cursorPos       int
	selectedPatches map[int]struct{} // currently pending selected patches

	vulnList      components.ViewModel
	unfixableList components.ViewModel
	patchInfo     []components.ViewModel
	resolveErrors components.ViewModel

	focusedInfo components.ViewModel // the ViewModel that is currently focused, nil if not focused
}

type relockCursorPos int

const (
	relockRemaining relockCursorPos = iota
	relockUnfixable
	relockErrors
	relockPatches
	relockApply
	relockWrite
	relockQuit
	relockEnd
)

func newStateRelockResult(m Model) stateRelockResult {
	st := stateRelockResult{
		currRes:         m.relockBaseManifest,
		currErrs:        m.relockBaseErrors,
		resolveErrors:   makeErrorsView(m.relockBaseErrors),
		patchesDone:     false,
		spinner:         components.NewSpinner(),
		cursorPos:       -1,
		selectedPatches: make(map[int]struct{}),
		vulnList:        components.NewVulnList(m.relockBaseManifest.Vulns, "", m.detailsRenderer),
	}
	st = st.ResizeInfo(m.viewWidth, m.viewHeight).(stateRelockResult)
	return st
}

// getEffectiveCursor gets the cursor position, accounting for the arbitrary number of patches
// returns relockPatches if over ANY of the patches
func (st stateRelockResult) getEffectiveCursor() relockCursorPos {
	if st.cursorPos < int(relockPatches) {
		return relockCursorPos(st.cursorPos)
	}

	if len(st.patches.Patches) == 0 {
		// skip over stateRelockPatches and stateRelockApply
		return relockCursorPos(st.cursorPos + 2)
	}

	if st.cursorPos < int(relockPatches)+len(st.patches.Patches) {
		return relockPatches
	}

	return relockCursorPos(st.cursorPos - len(st.patches.Patches) + 1)
}

// getEffectiveCursorFor gets the true cursor for the effective position,
// accounting for the arbitrary number of patches.
// getting relockPatches will get the position of the first patch.
func (st stateRelockResult) getEffectiveCursorFor(pos relockCursorPos) int {
	var offset int
	switch {
	case pos <= relockPatches:
		offset = 0
	case len(st.patches.Patches) == 0:
		offset = -2
	default:
		offset = len(st.patches.Patches) - 1
	}
	return int(pos) + offset
}

// getPatchIndex gets the index of the patch the cursor is currently over
func (st stateRelockResult) getPatchIndex() int {
	return st.cursorPos - int(relockPatches)
}

func (st stateRelockResult) Init(m Model) tea.Cmd {
	return tea.Batch(
		st.spinner.Tick,
		doComputeRelaxPatchesCmd(m.options, m.relockBaseManifest),
	)
}

func (st stateRelockResult) Update(m Model, msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case doRelockMsg: // finished resolving (after selecting multiple patches)
		if msg.err != nil {
			return errorAndExit(m, msg.err)
		}
		st.currRes = msg.resolvedManifest
		// recreate the vuln list info view
		st.vulnList = components.NewVulnList(st.currRes.Vulns, "", m.detailsRenderer)
		st.currErrs = computeResolveErrors(st.currRes.Graph)
		st.resolveErrors = makeErrorsView(st.currErrs)
		// Compute possible patches again
		st.patchesDone = false
		cmd = doComputeRelaxPatchesCmd(m.options, st.currRes)
	case relaxPatchMsg: // patch computation done
		if msg.err != nil {
			return errorAndExit(m, msg.err)
		}
		st.patches = msg.patches
		clear(st.selectedPatches)
		st = st.buildPatchInfoViews(m)
		st.patchesDone = true
		if len(st.patches.Patches) > 0 {
			// place the cursor on the first patch
			st.cursorPos = st.getEffectiveCursorFor(relockPatches)
		} else {
			// no patches, place the cursor on the 'write' line
			st.cursorPos = st.getEffectiveCursorFor(relockWrite)
		}

	case writeMsg: // just finished writing & installing the manifest
		if msg.err != nil {
			return errorAndExit(m, msg.err)
		}
		m.writing = false
		m.relockBaseManifest = st.currRes // relockBaseRes must match what is in the package.json
		m.relockBaseErrors = st.currErrs
		clear(st.selectedPatches)

	case components.ViewModelCloseMsg:
		// info view wants to quit, just unfocus it
		st.focusedInfo = nil
	case tea.KeyMsg:
		if !st.patchesDone { // Don't accept input in the middle of computation
			return m, nil
		}
		switch {
		case key.Matches(msg, components.Keys.SwitchView):
			if st.IsInfoFocused() {
				st.focusedInfo = nil
			} else if view, canFocus := st.currentInfoView(); canFocus {
				st.focusedInfo = view
			}
		case st.IsInfoFocused():
			st.focusedInfo, cmd = st.focusedInfo.Update(msg)
		case key.Matches(msg, components.Keys.Quit):
			// only quit if the cursor is over the quit line
			if st.getEffectiveCursor() == relockQuit {
				return m, tea.Quit
			}
			// move the cursor to the quit line if it's not already there
			st.cursorPos = st.getEffectiveCursorFor(relockQuit)
		case key.Matches(msg, components.Keys.Select): // enter key pressed
			return st.parseInput(m)
		// move the cursor
		case key.Matches(msg, components.Keys.Up):
			if st.getEffectiveCursor() > relockRemaining {
				st.cursorPos--
				if st.getEffectiveCursor() == relockErrors && len(st.currErrs) == 0 {
					st.cursorPos--
				}
			}
		case key.Matches(msg, components.Keys.Down):
			if st.getEffectiveCursor() < relockEnd-1 {
				st.cursorPos++
				if st.getEffectiveCursor() == relockErrors && len(st.currErrs) == 0 {
					st.cursorPos++
				}
			}
		}
	}
	var c tea.Cmd
	st.spinner, c = st.spinner.Update(msg)
	m.st = st

	return m, tea.Batch(cmd, c)
}

func (st stateRelockResult) currentInfoView() (view components.ViewModel, canFocus bool) {
	switch st.getEffectiveCursor() {
	case relockRemaining: // remaining vulns
		return st.vulnList, true
	case relockUnfixable: // unfixable vulns
		return st.unfixableList, true
	case relockErrors:
		return st.resolveErrors, false
	case relockPatches: // one of the patches
		return st.patchInfo[st.getPatchIndex()], true
	case relockApply:
		return components.TextView("Apply the selected patches and recompute vulnerabilities"), false
	case relockWrite:
		return components.TextView("Shell out to write manifest & lockfile"), false
	case relockQuit:
		return components.TextView("Exit Guided Remediation"), false
	case relockEnd:
		fallthrough
	default:
		return components.TextView(""), false // invalid (panic?)
	}
}

func (st stateRelockResult) buildPatchInfoViews(m Model) stateRelockResult {
	// create the info view for each of the patches
	// and the unfixable vulns
	st.patchInfo = nil
	for i, p := range st.patches.Patches {
		vulns := append(slices.Clone(st.currRes.Vulns), st.patches.Resolved[i].Vulns...)
		st.patchInfo = append(st.patchInfo, components.NewRelockInfo(p, vulns, m.detailsRenderer))
	}

	unfixableVulns := relockUnfixableVulns(st.currRes.Vulns, st.patches.Patches)
	st.unfixableList = components.NewVulnList(unfixableVulns, "", m.detailsRenderer)
	st.numUnfixable = len(unfixableVulns)
	return st.ResizeInfo(m.viewWidth, m.viewHeight).(stateRelockResult)
}

func relockUnfixableVulns(allVulns []resolution.Vulnerability, patches []result.Patch) []resolution.Vulnerability {
	if len(allVulns) == 0 {
		return nil
	}
	if len(patches) == 0 {
		return allVulns
	}

	// find every vuln ID fixed in any patch
	fixableVulnIDs := make(map[string]struct{})
	for _, p := range patches {
		for _, v := range p.Fixed {
			fixableVulnIDs[v.ID] = struct{}{}
		}
	}
	var unfixableVulns []resolution.Vulnerability
	for _, v := range allVulns {
		if _, ok := fixableVulnIDs[v.OSV.ID]; !ok {
			unfixableVulns = append(unfixableVulns, v)
		}
	}
	return unfixableVulns
}

func (st stateRelockResult) parseInput(m Model) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch st.getEffectiveCursor() {
	case relockRemaining: // vuln line, focus info view
		st.focusedInfo = st.vulnList
	case relockUnfixable: // unfixable vulns line, focus info view
		st.focusedInfo = st.unfixableList
	case relockPatches: // patch selected
		idx := st.getPatchIndex()
		if _, ok := st.selectedPatches[idx]; ok { // if already selected, deselect it
			delete(st.selectedPatches, idx)
		} else if st.patchCompatible(idx) { // if it's compatible with current other selections, select it
			st.selectedPatches[idx] = struct{}{}
		}
	case relockApply: // apply changes
		if len(st.selectedPatches) > 0 {
			return st.relaxChoice(m)
		}
	case relockWrite: // write
		m.writing = true
		cmd = func() tea.Msg { return st.write(m) }
	case relockQuit: // quit
		cmd = tea.Quit
	case relockErrors, relockEnd:
	}

	m.st = st
	return m, cmd
}

func (st stateRelockResult) relaxChoice(m Model) (tea.Model, tea.Cmd) {
	// Compute combined changes and re-resolve the graph
	manifest := st.currRes.Manifest.Clone()
	for i := range st.selectedPatches {
		for _, p := range st.patches.Patches[i].PackageUpdates {
			err := manifest.PatchRequirement(resolve.RequirementVersion{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						Name:   p.Name,
						System: m.manifestRW.System(),
					},
					Version:     p.VersionTo,
					VersionType: resolve.Requirement,
				},
				Type: p.Type.Clone(),
			})
			if err != nil {
				return errorAndExit(m, err)
			}
		}
	}

	st.currRes = nil
	m.st = st
	return m, doRelockCmd(m.options, manifest)
}

func (st stateRelockResult) View(m Model) string {
	if m.writing {
		return ""
	}
	s := strings.Builder{}
	s.WriteString("RELOCK\n")
	if st.currRes == nil {
		s.WriteString("Resolving dependency graph ")
		s.WriteString(st.spinner.View())
		s.WriteString("\n")

		return s.String()
	}

	s.WriteString(components.RenderSelectorOption(
		st.getEffectiveCursor() == relockRemaining,
		"",
		"%s remain\n",
		fmt.Sprintf("%d vulnerabilities", len(st.currRes.Vulns)),
	))

	if !st.patchesDone {
		s.WriteString("\n")
		s.WriteString("Computing possible patches ")
		s.WriteString(st.spinner.View())
		s.WriteString("\n")

		return s.String()
	}

	s.WriteString(components.RenderSelectorOption(
		st.getEffectiveCursor() == relockUnfixable,
		"",
		"%s are unfixable\n",
		fmt.Sprintf("%d vulnerabilities", st.numUnfixable),
	))

	if len(st.currErrs) > 0 {
		s.WriteString(components.RenderSelectorOption(
			st.getEffectiveCursor() == relockErrors,
			"",
			"WARNING: Encountered %s during graph resolution.\n",
			fmt.Sprintf("%d errors", len(st.currErrs)),
		))
	}
	s.WriteString("\n")

	if len(st.patches.Patches) == 0 {
		s.WriteString("No remaining vulnerabilities can be fixed.\n")
	} else {
		s.WriteString("Actions:\n")
		patchStrs := make([]string, len(st.patches.Patches))
		for i, patch := range st.patches.Patches {
			var checkBox string
			if _, ok := st.selectedPatches[i]; ok {
				checkBox = "[x]"
			} else {
				checkBox = "[ ]"
			}
			if !st.patchCompatible(i) {
				checkBox = components.DisabledTextStyle.Render(checkBox)
			}
			checkBox = components.RenderSelectorOption(
				st.getEffectiveCursor() == relockPatches && st.getPatchIndex() == i,
				" > ",
				"%s ",
				checkBox,
			)
			text := patchString(patch)
			var textSt lipgloss.Style
			if st.patchCompatible(i) {
				textSt = lipgloss.NewStyle()
			} else {
				textSt = components.DisabledTextStyle
			}
			text = textSt.Width(m.viewWidth - lipgloss.Width(checkBox)).Render(text)
			patchStrs[i] = lipgloss.JoinHorizontal(lipgloss.Top, checkBox, text)
		}
		s.WriteString(lipgloss.JoinVertical(lipgloss.Left, patchStrs...))
		s.WriteString("\n")

		if len(st.selectedPatches) > 0 {
			s.WriteString(components.RenderSelectorOption(
				st.getEffectiveCursor() == relockApply,
				"> ",
				"%s pending patches\n",
				"Apply",
			))
		} else {
			s.WriteString(components.RenderSelectorOption(
				st.getEffectiveCursor() == relockApply,
				"> ",
				components.DisabledTextStyle.Render("No pending patches")+"\n",
			))
		}
	}

	s.WriteString(components.RenderSelectorOption(
		st.getEffectiveCursor() == relockWrite,
		"> ",
		"%s changes to manifest\n",
		"Write",
	))
	s.WriteString("\n")
	s.WriteString(components.RenderSelectorOption(
		st.getEffectiveCursor() == relockQuit,
		"> ",
		"%s without saving changes\n",
		"quit",
	))

	return s.String()
}

func patchString(patch result.Patch) string {
	var depStr string
	if len(patch.PackageUpdates) == 1 {
		pkg := patch.PackageUpdates[0]
		depStr = fmt.Sprintf("%s@%s → @%s", pkg.Name, pkg.VersionFrom, pkg.VersionTo)
	} else {
		depStr = fmt.Sprintf("%d packages", len(patch.PackageUpdates))
	}
	str := fmt.Sprintf("Upgrading %s resolves %d vulns", depStr, len(patch.Fixed))
	if len(patch.Introduced) > 0 {
		str += fmt.Sprintf(" but introduces %d new vulns", len(patch.Introduced))
	}

	return str
}

func (st stateRelockResult) InfoView() string {
	v, _ := st.currentInfoView()
	return v.View()
}

// check if a patch is compatible with the currently selected patches
// i.e. if none of the direct dependencies in the current patch appear in the already selected patches
func (st stateRelockResult) patchCompatible(idx int) bool {
	if _, ok := st.selectedPatches[idx]; ok {
		// already selected, it must be compatible
		return true
	}
	// find any shared direct dependency packages
	patch := st.patches.Patches[idx]
	for i := range st.selectedPatches {
		curr := st.patches.Patches[i]
		for _, dep := range curr.PackageUpdates {
			for _, newDep := range patch.PackageUpdates {
				if dep.Name == newDep.Name {
					return false
				}
			}
		}
	}

	return true
}

func (st stateRelockResult) Resize(_, _ int) modelState {
	return st
}

func (st stateRelockResult) ResizeInfo(w, h int) modelState {
	st.vulnList = st.vulnList.Resize(w, h)
	for i, info := range st.patchInfo {
		st.patchInfo[i] = info.Resize(w, h)
	}
	return st
}

func (st stateRelockResult) IsInfoFocused() bool {
	return st.focusedInfo != nil
}

func (st stateRelockResult) write(m Model) tea.Msg {
	patches := remediation.ConstructPatches(m.relockBaseManifest, st.currRes)
	err := parser.WriteManifestPatches(
		m.options.Manifest,
		m.relockBaseManifest.Manifest,
		[]result.Patch{patches},
		m.manifestRW,
	)
	if err != nil {
		return writeMsg{err}
	}

	if m.options.Lockfile == "" {
		// Unfortunately, there's no user feedback to show this was successful
		return writeMsg{nil}
	}

	// shell out to npm to write the package-lock.json file.
	dir := filepath.Dir(m.options.Manifest)
	npmPath, err := exec.LookPath("npm")
	if err != nil {
		return writeMsg{fmt.Errorf("cannot find npm executable: %w", err)}
	}

	// Must remove preexisting package-lock.json and node_modules directory for a clean install.
	// Use RemoveAll to avoid errors if the files doesn't exist.
	if err := os.RemoveAll(filepath.Join(dir, "package-lock.json")); err != nil {
		return fmt.Errorf("failed removing old package-lock.json/: %w", err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "node_modules")); err != nil {
		return fmt.Errorf("failed removing old node_modules/: %w", err)
	}

	c := exec.CommandContext(context.Background(), npmPath, "install", "--package-lock-only")
	c.Dir = dir

	return tea.ExecProcess(c, func(err error) tea.Msg {
		if err != nil {
			// try again with "--legacy-peer-deps"
			c = exec.CommandContext(context.Background(), npmPath, "install", "--package-lock-only", "--legacy-peer-deps")
			c.Dir = dir

			return tea.ExecProcess(c, func(err error) tea.Msg { return writeMsg{err} })()
		}

		return writeMsg{err}
	})()
}

func doRelockCmd(opts options.FixVulnsOptions, m manifest.Manifest) tea.Cmd {
	return func() tea.Msg {
		resolved, err := remediation.ResolveManifest(context.Background(), opts.ResolveClient, opts.MatcherClient, m, &opts.RemediationOptions)
		if err != nil {
			return doRelockMsg{err: fmt.Errorf("failed resolving manifest vulnerabilities: %w", err)}
		}
		return doRelockMsg{resolvedManifest: resolved}
	}
}

type relaxPatchMsg struct {
	patches common.PatchResult
	err     error
}

func doComputeRelaxPatchesCmd(opts options.FixVulnsOptions, resolved *remediation.ResolvedManifest) tea.Cmd {
	return func() tea.Msg {
		patches, err := relax.ComputePatches(context.Background(), opts.ResolveClient, opts.MatcherClient, resolved, &opts.RemediationOptions)
		if err != nil {
			return relaxPatchMsg{err: fmt.Errorf("failed computing relax patches: %w", err)}
		}
		return relaxPatchMsg{patches: patches}
	}
}
