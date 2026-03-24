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

package model

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"deps.dev/util/resolve"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/osv-scalibr/guidedremediation/internal/remediation"
	"github.com/google/osv-scalibr/guidedremediation/internal/resolution"
	"github.com/google/osv-scalibr/guidedremediation/internal/strategy/inplace"
	"github.com/google/osv-scalibr/guidedremediation/internal/tui/components"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/result"
)

type stateChooseStrategy struct {
	cursorPos chooseStratCursorPos
	canRelock bool

	vulnCount vulnCount

	vulnList       components.ViewModel
	inPlaceInfo    components.ViewModel
	relockFixVulns components.ViewModel
	errorsView     components.ViewModel

	depthInput    textinput.Model
	severityInput textinput.Model

	focusedInfo components.ViewModel // the infoview that is currently focused, nil if not focused
}

type chooseStratCursorPos int

const (
	chooseStratInfo chooseStratCursorPos = iota
	chooseStratErrors
	chooseStratInPlace
	chooseStratRelock
	chooseStratDepth
	chooseStratSeverity
	chooseStratDev
	chooseStratApplyCriteria
	chooseStratQuit
	chooseStratEnd
)

func newStateChooseStrategy(m Model) stateChooseStrategy {
	s := stateChooseStrategy{
		cursorPos: chooseStratInPlace,
	}

	// pre-generate the info views for each option
	s.vulnList = components.NewVulnList(m.lockfileGraph.Vulns, "", m.detailsRenderer)

	// make the in-place view
	s.inPlaceInfo = components.NewInPlaceInfo(m.lockfilePatches, m.lockfileGraph.Vulns, m.detailsRenderer)

	if m.options.Manifest != "" {
		var relockFixes []resolution.Vulnerability
		for _, v := range m.lockfileGraph.Vulns {
			if !slices.ContainsFunc(m.relockBaseManifest.Vulns, func(r resolution.Vulnerability) bool {
				return r.OSV.Id == v.OSV.Id
			}) {
				relockFixes = append(relockFixes, v)
			}
		}
		s.canRelock = true
		s.relockFixVulns = components.NewVulnList(relockFixes, "Relocking fixes the following vulns:", m.detailsRenderer)
	} else {
		s.canRelock = false
		s.relockFixVulns = components.TextView("Re-run with manifest to resolve vulnerabilities by re-locking")
	}

	s.depthInput = textinput.New()
	s.depthInput.CharLimit = 3
	s.depthInput.SetValue(strconv.Itoa(m.options.MaxDepth))

	s.severityInput = textinput.New()
	s.severityInput.CharLimit = 4
	s.severityInput.SetValue(strconv.FormatFloat(m.options.MinSeverity, 'g', -1, 64))

	s.errorsView = makeErrorsView(m.relockBaseErrors)

	s.vulnCount = countVulns(m.lockfileGraph.Vulns, m.options.RemediationOptions)

	return s
}

func (s stateChooseStrategy) Init(m Model) tea.Cmd {
	return nil
}

func (s stateChooseStrategy) Update(m Model, msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case components.ViewModelCloseMsg:
		// info view wants to quit, just unfocus it
		s.focusedInfo = nil
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, components.Keys.SwitchView):
			if s.IsInfoFocused() {
				s.focusedInfo = nil
			} else if view, canFocus := s.currentInfoView(); canFocus {
				s.focusedInfo = view
			}
		case s.IsInfoFocused():
			var cmd tea.Cmd
			s.focusedInfo, cmd = s.focusedInfo.Update(msg)

			return m, cmd
		case key.Matches(msg, components.Keys.Quit):
			// only quit if the cursor is over the quit line
			if s.cursorPos == chooseStratQuit {
				return m, tea.Quit
			}
			// otherwise move the cursor to the quit line if it's not already there
			s.cursorPos = chooseStratQuit
		case key.Matches(msg, components.Keys.Select):
			// enter key was pressed, parse input
			return s.parseInput(m)
		// move the cursor and show the corresponding info view
		case key.Matches(msg, components.Keys.Up):
			if s.cursorPos > chooseStratInfo {
				s.cursorPos--
				// Resolution errors aren't rendered if there are none
				if s.cursorPos == chooseStratErrors && len(m.relockBaseErrors) == 0 {
					s.cursorPos--
				}
			}
			s = s.UpdateTextFocus()
		case key.Matches(msg, components.Keys.Down):
			if s.cursorPos < chooseStratEnd-1 {
				s.cursorPos++
				if s.cursorPos == chooseStratErrors && len(m.relockBaseErrors) == 0 {
					s.cursorPos++
				}
			}
			s = s.UpdateTextFocus()
		}
	}

	var cmd tea.Cmd
	s.depthInput, cmd = s.depthInput.Update(msg)
	cmds = append(cmds, cmd)

	s.severityInput, cmd = s.severityInput.Update(msg)
	cmds = append(cmds, cmd)

	m.st = s
	return m, tea.Batch(cmds...)
}

func (s stateChooseStrategy) UpdateTextFocus() stateChooseStrategy {
	s.depthInput.Blur()
	s.severityInput.Blur()

	switch s.cursorPos {
	case chooseStratDepth:
		s.depthInput.Focus()
	case chooseStratSeverity:
		s.severityInput.Focus()
	case
		chooseStratInfo,
		chooseStratErrors,
		chooseStratInPlace,
		chooseStratRelock,
		chooseStratDev,
		chooseStratApplyCriteria,
		chooseStratQuit,
		chooseStratEnd:
	}
	return s
}

func (s stateChooseStrategy) IsInfoFocused() bool {
	return s.focusedInfo != nil
}

func (s stateChooseStrategy) currentInfoView() (view components.ViewModel, canFocus bool) {
	switch s.cursorPos {
	case chooseStratInfo: // info line
		return s.vulnList, true
	case chooseStratErrors:
		return s.errorsView, false
	case chooseStratInPlace: // in-place
		return s.inPlaceInfo, true
	case chooseStratRelock: // relock
		return s.relockFixVulns, s.canRelock
	case chooseStratQuit: // quit
		return components.TextView("Exit Guided Remediation"), false
	case
		chooseStratDepth,
		chooseStratSeverity,
		chooseStratDev,
		chooseStratApplyCriteria,
		chooseStratEnd:
		fallthrough
	default:
		return components.TextView(""), false
	}
}

func (s stateChooseStrategy) parseInput(m Model) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch s.cursorPos {
	case chooseStratInfo: // info line, focus on info view
		s.focusedInfo = s.vulnList
		m.st = s
	case chooseStratInPlace: // in-place
		m.st = newStateInPlaceResult(m, s.inPlaceInfo, nil)
		cmd = m.st.Init(m)
	case chooseStratRelock: // relock
		if s.canRelock {
			m.st = newStateRelockResult(m)
			cmd = m.st.Init(m)
		}
	case chooseStratDev:
		m.options.DevDeps = !m.options.DevDeps
	case chooseStratApplyCriteria:
		maxDepth, err := strconv.Atoi(s.depthInput.Value())
		if err == nil {
			m.options.MaxDepth = maxDepth
		}

		minSeverity, err := strconv.ParseFloat(s.severityInput.Value(), 64)
		if err == nil {
			m.options.MinSeverity = minSeverity
		}

		// Recompute vulns/patches with the new filters.
		fn := func(v resolution.Vulnerability) bool { return !remediation.MatchVuln(m.options.RemediationOptions, v) }
		m.lockfileGraph.Vulns = slices.Clone(m.lockfileGraph.UnfilteredVulns)
		m.lockfileGraph.Vulns = slices.DeleteFunc(m.lockfileGraph.Vulns, fn)
		m.lockfilePatches, err = inplace.ComputePatches(context.Background(), m.options.ResolveClient, m.lockfileGraph, &m.options.RemediationOptions)
		if err != nil {
			return errorAndExit(m, err)
		}
		if m.relockBaseManifest != nil {
			m.relockBaseManifest.Vulns = slices.Clone(m.relockBaseManifest.UnfilteredVulns)
			m.relockBaseManifest.Vulns = slices.DeleteFunc(m.relockBaseManifest.Vulns, fn)
		}

		m.st = newStateChooseStrategy(m)
		cmd = m.st.Init(m)
	case chooseStratQuit: // quit line
		cmd = tea.Quit
	case
		chooseStratErrors,
		chooseStratDepth,
		chooseStratSeverity,
		chooseStratEnd:
	}

	return m, cmd
}

func (s stateChooseStrategy) View(m Model) string {
	vulnCount := s.vulnCount
	fixCount := vulnCount.total
	pkgChange := 0
	for _, p := range m.lockfilePatches {
		fixCount -= len(p.Fixed)
		pkgChange += len(p.PackageUpdates)
	}

	sb := strings.Builder{}
	sb.WriteString(components.RenderSelectorOption(
		s.cursorPos == chooseStratInfo,
		"",
		fmt.Sprintf("Found %%s in lockfile (%d direct, %d transitive, %d dev only) matching the criteria.\n",
			vulnCount.direct, vulnCount.transitive, vulnCount.devOnly),
		fmt.Sprintf("%d vulnerabilities", vulnCount.total),
	))
	if len(m.relockBaseErrors) > 0 {
		sb.WriteString(components.RenderSelectorOption(
			s.cursorPos == chooseStratErrors,
			"",
			"WARNING: Encountered %s during graph resolution.\n",
			fmt.Sprintf("%d errors", len(m.relockBaseErrors)),
		))
	}
	sb.WriteString("\n")
	sb.WriteString("Actions:\n")
	sb.WriteString(components.RenderSelectorOption(
		s.cursorPos == chooseStratInPlace,
		" > ",
		fmt.Sprintf("%%s (fixes %d/%d vulns, changes %d packages)\n", fixCount, vulnCount.total, pkgChange),
		"Modify lockfile in-place",
	))

	if s.canRelock {
		relockFix := vulnCount.total - len(m.relockBaseManifest.Vulns)
		sb.WriteString(components.RenderSelectorOption(
			s.cursorPos == chooseStratRelock,
			" > ",
			fmt.Sprintf("%%s (fixes %d/%d vulns) and try direct dependency upgrades\n", relockFix, vulnCount.total),
			"Re-lock project",
		))
	} else {
		sb.WriteString(components.RenderSelectorOption(
			s.cursorPos == chooseStratRelock,
			" > ",
			components.DisabledTextStyle.Render("Cannot re-lock - missing manifest file\n"),
		))
	}
	sb.WriteString("\n")
	sb.WriteString("Criteria:\n")
	sb.WriteString(components.RenderSelectorOption(
		s.cursorPos == chooseStratDepth,
		" > ",
		fmt.Sprintf("%%s: %s\n", s.depthInput.View()),
		"Max dependency depth",
	))
	sb.WriteString(components.RenderSelectorOption(
		s.cursorPos == chooseStratSeverity,
		" > ",
		fmt.Sprintf("%%s: %s\n", s.severityInput.View()),
		"Min CVSS score",
	))

	devString := "YES"
	if m.options.DevDeps {
		devString = "NO"
	}
	sb.WriteString(components.RenderSelectorOption(
		s.cursorPos == chooseStratDev,
		" > ",
		fmt.Sprintf("%%s: %s\n", devString),
		"Exclude dev only",
	))
	sb.WriteString(components.RenderSelectorOption(
		s.cursorPos == chooseStratApplyCriteria,
		" > ",
		"%s\n",
		"Apply criteria",
	))

	sb.WriteString("\n")
	sb.WriteString(components.RenderSelectorOption(
		s.cursorPos == chooseStratQuit,
		"> ",
		"%s\n",
		"quit",
	))

	return sb.String()
}

func (s stateChooseStrategy) InfoView() string {
	v, _ := s.currentInfoView()
	return v.View()
}

func (s stateChooseStrategy) Resize(_, _ int) modelState { return s }

func (s stateChooseStrategy) ResizeInfo(w, h int) modelState {
	s.vulnList = s.vulnList.Resize(w, h)
	s.inPlaceInfo = s.inPlaceInfo.Resize(w, h)
	s.relockFixVulns = s.relockFixVulns.Resize(w, h)

	return s
}

type vulnCount struct {
	total      int
	direct     int
	transitive int
	devOnly    int
}

func countVulns(vulns []resolution.Vulnerability, opts options.RemediationOptions) vulnCount {
	var vc vulnCount
	for _, v := range vulns {
		// count vulns per in-place, i.e. unique per ID & package version.
		seen := make(map[resolve.VersionKey]struct{})
		nonDev := make(map[resolve.VersionKey]struct{})
		seenAsDirect := make(map[resolve.VersionKey]struct{})
		for _, sg := range v.Subgraphs {
			devOnly := sg.IsDevOnly(nil)
			// check if the vulnerability should be filtered out.
			if !remediation.MatchVuln(opts, resolution.Vulnerability{
				OSV:       v.OSV,
				Subgraphs: []*resolution.DependencySubgraph{sg},
				DevOnly:   devOnly,
			}) {
				continue
			}
			node := sg.Nodes[sg.Dependency]
			vk := node.Version
			seen[vk] = struct{}{}
			if slices.ContainsFunc(node.Parents, func(e resolve.Edge) bool { return e.From == 0 }) {
				seenAsDirect[vk] = struct{}{}
			}
			if !devOnly {
				nonDev[vk] = struct{}{}
			}
		}
		for vk := range seen {
			vc.total++
			if _, ok := nonDev[vk]; !ok {
				vc.devOnly++
			}
			if _, ok := seenAsDirect[vk]; ok {
				vc.direct++
			} else {
				vc.transitive++
			}
		}
	}

	return vc
}

func makeErrorsView(errs []result.ResolveError) components.ViewModel {
	if len(errs) == 0 {
		return components.TextView("")
	}

	s := strings.Builder{}
	s.WriteString("The following errors were encountered during resolution which may impact results:\n")
	for _, e := range errs {
		fmt.Fprintf(&s, "Error when resolving %s@%s:\n", e.Package.Name, e.Package.Version)
		if strings.Contains(e.Requirement.Version, ":") {
			// this will be the case with unsupported npm requirements e.g. `file:...`, `git+https://...`
			// No easy access to the `knownAs` field to find which package this corresponds to...
			fmt.Fprintf(&s, "\tSkipped resolving unsupported version specification: %s\n", e.Requirement.Version)
		} else {
			fmt.Fprintf(&s, "\t%v: %s@%s\n", e.Error, e.Requirement.Name, e.Requirement.Version)
		}
	}
	return components.TextView(s.String())
}
