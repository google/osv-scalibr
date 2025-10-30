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
	"fmt"
	"slices"
	"strings"

	"deps.dev/util/resolve"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/osv-scalibr/guidedremediation/internal/parser"
	"github.com/google/osv-scalibr/guidedremediation/internal/remediation"
	"github.com/google/osv-scalibr/guidedremediation/internal/resolution"
	"github.com/google/osv-scalibr/guidedremediation/internal/tui/components"
	"github.com/google/osv-scalibr/guidedremediation/result"
)

type stateInPlaceResult struct {
	cursorPos inPlaceCursorPos
	canRelock bool

	selectedChanges []bool

	vulnList       components.ViewModel
	inPlaceInfo    components.ViewModel
	relockFixVulns components.ViewModel

	focusedInfo components.ViewModel
}

type inPlaceCursorPos int

const (
	inPlaceFixed inPlaceCursorPos = iota
	inPlaceRemain
	inPlaceChoice
	inPlaceWrite
	inPlaceRelock
	inPlaceQuit
	inPlaceEnd
)

func newStateInPlaceResult(m Model, inPlaceInfo components.ViewModel, selectedChanges []bool) stateInPlaceResult {
	s := stateInPlaceResult{
		cursorPos:   inPlaceChoice,
		inPlaceInfo: inPlaceInfo,
	}

	// If created without a selection, choose all compatible patches.
	if selectedChanges == nil {
		selectedChanges = chooseAllCompatiblePatches(m.lockfilePatches)
	}
	s.selectedChanges = selectedChanges

	// pre-generate the info views for each option
	// Get the list of remaining vulns
	vulns := inPlaceUnfixable(m)
	s.vulnList = components.NewVulnList(vulns, "", m.detailsRenderer)

	// recompute the vulns fixed by relocking after the in-place update
	if m.options.Manifest != "" {
		s.canRelock = true
		var relockFixes []resolution.Vulnerability
		for _, v := range vulns {
			if !slices.ContainsFunc(m.relockBaseManifest.Vulns, func(r resolution.Vulnerability) bool {
				return r.OSV.Id == v.OSV.Id
			}) {
				relockFixes = append(relockFixes, v)
			}
		}
		s.relockFixVulns = components.NewVulnList(relockFixes, "Relocking fixes the following vulns:", m.detailsRenderer)
	} else {
		s.canRelock = false
		s.relockFixVulns = components.TextView("Re-run with manifest to resolve vulnerabilities by re-locking")
	}

	s = s.ResizeInfo(m.viewWidth, m.viewHeight).(stateInPlaceResult)
	return s
}

func (st stateInPlaceResult) Init(m Model) tea.Cmd {
	return nil
}

func (st stateInPlaceResult) Update(m Model, msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case writeMsg: // just finished writing & installing the lockfile
		if msg.err != nil {
			return errorAndExit(m, msg.err)
		}
		// re-parse the lockfile
		cmd = doInPlaceResolutionCmd(m.options, m.lockfileRW)
	case inPlaceResolutionMsg:
		if msg.err != nil {
			return errorAndExit(m, msg.err)
		}
		m.writing = false
		m.lockfilePatches = msg.allPatches
		m.lockfileGraph = msg.resolvedGraph
		st.selectedChanges = make([]bool, len(m.lockfilePatches)) // unselect all patches
		st.inPlaceInfo = components.NewInPlaceInfo(m.lockfilePatches, m.lockfileGraph.Vulns, m.detailsRenderer)
	case components.ViewModelCloseMsg:
		// info view wants to quit, just unfocus it
		st.focusedInfo = nil
	case tea.KeyMsg:
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
			if st.cursorPos == inPlaceQuit {
				return m, tea.Quit
			}
			// move the cursor to the quit line if it's not already there
			st.cursorPos = inPlaceQuit
		case key.Matches(msg, components.Keys.Select):
			// enter key was pressed, parse input
			return st.parseInput(m)
		// move the cursor and show the corresponding info view
		case key.Matches(msg, components.Keys.Up):
			if st.cursorPos > inPlaceFixed {
				st.cursorPos--
			}
		case key.Matches(msg, components.Keys.Down):
			if st.cursorPos < inPlaceEnd-1 {
				st.cursorPos++
			}
		}
	}

	m.st = st
	return m, cmd
}

func (st stateInPlaceResult) currentInfoView() (view components.ViewModel, canFocus bool) {
	switch st.cursorPos {
	case inPlaceFixed: // info - fixed vulns
		return st.inPlaceInfo, true
	case inPlaceRemain: // info - remaining vulns
		return st.vulnList, true
	case inPlaceChoice: // choose changes
		return components.TextView("Choose which changes to apply"), false
	case inPlaceWrite: // write
		return components.TextView("Write changes to lockfile"), false
	case inPlaceRelock: // relock
		return st.relockFixVulns, st.canRelock
	case inPlaceQuit: // quit
		return components.TextView("Exit Guided Remediation"), false
	case inPlaceEnd:
		fallthrough
	default:
		return components.TextView(""), false
	}
}

func (st stateInPlaceResult) parseInput(m Model) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch st.cursorPos {
	case inPlaceFixed, inPlaceRemain: // info lines, focus info view
		v, _ := st.currentInfoView()
		st.focusedInfo = v
	case inPlaceChoice: // choose specific patches
		m.st = newStateChooseInPlacePatches(m, st)
		cmd = m.st.Init(m)
		return m, cmd
	case inPlaceWrite: // write
		m.writing = true
		cmd = func() tea.Msg { return st.write(m) }
	case inPlaceRelock: // relock
		if st.canRelock {
			m.st = newStateRelockResult(m)
			cmd = m.st.Init(m)
			return m, cmd
		}
	case inPlaceQuit: // quit
		cmd = tea.Quit
	case inPlaceEnd:
	}
	m.st = st

	return m, cmd
}

func (st stateInPlaceResult) View(m Model) string {
	if m.writing {
		return ""
	}
	remainCount := len(inPlaceUnfixable(m))
	fixCount := countVulns(m.lockfileGraph.Vulns, m.options.RemediationOptions).total - remainCount
	pkgCount := len(m.lockfilePatches)
	nSelected := 0
	for _, s := range st.selectedChanges {
		if s {
			nSelected++
		}
	}

	s := strings.Builder{}
	s.WriteString("IN-PLACE\n")
	s.WriteString(components.RenderSelectorOption(
		st.cursorPos == inPlaceFixed,
		"",
		fmt.Sprintf("%%s can be changed, fixing %d vulnerabilities\n", fixCount),
		fmt.Sprintf("%d packages", pkgCount),
	))
	s.WriteString(components.RenderSelectorOption(
		st.cursorPos == inPlaceRemain,
		"",
		"%s remain\n",
		fmt.Sprintf("%d vulnerabilities", remainCount),
	))

	s.WriteString("\n")

	s.WriteString("Actions:\n")
	s.WriteString(components.RenderSelectorOption(
		st.cursorPos == inPlaceChoice,
		" > ",
		"%s which changes to apply\n",
		"Choose",
	))
	s.WriteString(components.RenderSelectorOption(
		st.cursorPos == inPlaceWrite,
		" > ",
		fmt.Sprintf("%%s %d changes to lockfile\n", nSelected),
		"Write",
	))
	if st.canRelock {
		s.WriteString(components.RenderSelectorOption(
			st.cursorPos == inPlaceRelock,
			" > ",
			"%s the whole project instead\n",
			"Relock",
		))
	} else {
		s.WriteString(components.RenderSelectorOption(
			st.cursorPos == inPlaceRelock,
			" > ",
			components.DisabledTextStyle.Render("Cannot re-lock - missing manifest file\n"),
		))
	}
	s.WriteString("\n")
	s.WriteString(components.RenderSelectorOption(
		st.cursorPos == inPlaceQuit,
		"> ",
		"%s without saving changes\n",
		"quit",
	))

	return s.String()
}

func (st stateInPlaceResult) InfoView() string {
	v, _ := st.currentInfoView()
	return v.View()
}

func (st stateInPlaceResult) Resize(_, _ int) modelState { return st }

func (st stateInPlaceResult) ResizeInfo(w, h int) modelState {
	st.inPlaceInfo = st.inPlaceInfo.Resize(w, h)
	st.vulnList = st.vulnList.Resize(w, h)
	st.relockFixVulns = st.relockFixVulns.Resize(w, h)
	return st
}

func (st stateInPlaceResult) IsInfoFocused() bool {
	return st.focusedInfo != nil
}

func (st stateInPlaceResult) write(m Model) tea.Msg {
	var patches []result.Patch
	for i, p := range m.lockfilePatches {
		if st.selectedChanges[i] {
			patches = append(patches, p)
		}
	}

	return writeMsg{parser.WriteLockfilePatches(m.options.Lockfile, patches, m.lockfileRW)}
}

func chooseAllCompatiblePatches(allPatches []result.Patch) []bool {
	choices := make([]bool, len(allPatches))
	pkgChanges := make(map[result.Package]struct{}) // dependencies we've already applied a patch to
	type vulnIdentifier struct {
		id         string
		pkgName    string
		pkgVersion string
	}
	fixedVulns := make(map[vulnIdentifier]struct{}) // vulns that have already been fixed by a patch
	for i, patch := range allPatches {
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
			identifier := vulnIdentifier{
				id:         v.ID,
				pkgName:    patch.PackageUpdates[0].Name,
				pkgVersion: patch.PackageUpdates[0].VersionFrom,
			}
			_, ok := fixedVulns[identifier]
			return ok
		}) {
			continue
		}

		choices[i] = true
		for _, pkg := range patch.PackageUpdates {
			pkgChanges[result.Package{Name: pkg.Name, Version: pkg.VersionFrom}] = struct{}{}
		}
		for _, v := range patch.Fixed {
			identifier := vulnIdentifier{
				id:         v.ID,
				pkgName:    patch.PackageUpdates[0].Name,
				pkgVersion: patch.PackageUpdates[0].VersionFrom,
			}
			fixedVulns[identifier] = struct{}{}
		}
	}
	return choices
}

func inPlaceUnfixable(m Model) []resolution.Vulnerability {
	var vulns []resolution.Vulnerability
	for _, vuln := range m.lockfileGraph.Vulns {
		seenPkgsVulnIdx := make(map[resolve.VersionKey]int)
		for _, sg := range vuln.Subgraphs {
			v := resolution.Vulnerability{
				OSV:       vuln.OSV,
				Subgraphs: []*resolution.DependencySubgraph{sg},
				DevOnly:   sg.IsDevOnly(nil),
			}
			if !remediation.MatchVuln(m.options.RemediationOptions, v) {
				continue
			}
			node := sg.Nodes[sg.Dependency]
			if idx, ok := seenPkgsVulnIdx[node.Version]; ok {
				vulns[idx].Subgraphs = append(vulns[idx].Subgraphs, sg)
				vulns[idx].DevOnly = vulns[idx].DevOnly && v.DevOnly
				continue
			}
			if !slices.ContainsFunc(m.lockfilePatches, func(p result.Patch) bool {
				fixesVulnID := slices.ContainsFunc(p.Fixed, func(rv result.Vuln) bool {
					return rv.ID == v.OSV.Id
				})
				changesPackage := slices.ContainsFunc(p.PackageUpdates, func(p result.PackageUpdate) bool {
					return p.Name == node.Version.Name && p.VersionFrom == node.Version.Version
				})
				return fixesVulnID && changesPackage
			}) {
				vulns = append(vulns, v)
				seenPkgsVulnIdx[node.Version] = len(vulns) - 1
			}
		}
	}
	return vulns
}
