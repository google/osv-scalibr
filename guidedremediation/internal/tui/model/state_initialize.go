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
	"strings"

	"deps.dev/util/resolve"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/osv-scalibr/guidedremediation/internal/lockfile"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/internal/parser"
	"github.com/google/osv-scalibr/guidedremediation/internal/remediation"
	"github.com/google/osv-scalibr/guidedremediation/internal/strategy/inplace"
	"github.com/google/osv-scalibr/guidedremediation/internal/tui/components"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/result"
)

type stateInitialize struct {
	spinner spinner.Model
}

func newStateInitialize() stateInitialize {
	return stateInitialize{
		spinner: components.NewSpinner(),
	}
}

func (s stateInitialize) Init(m Model) tea.Cmd {
	cmds := []tea.Cmd{s.spinner.Tick}
	if m.options.Lockfile != "" {
		// if we have a lockfile, start calculating the in-place updates
		cmds = append(cmds, doInPlaceResolutionCmd(m.options, m.lockfileRW))
	} else {
		// if we don't have a lockfile, start calculating the relock result
		cmds = append(cmds, doInitialRelockCmd(m.options, m.manifestRW))
	}

	return tea.Batch(cmds...)
}

func (s stateInitialize) Update(m Model, msg tea.Msg) (tea.Model, tea.Cmd) {
	var c tea.Cmd
	s.spinner, c = s.spinner.Update(msg)
	m.st = s
	cmds := []tea.Cmd{c}
	switch msg := msg.(type) {
	// in-place resolution finished
	case inPlaceResolutionMsg:
		if msg.err != nil {
			return errorAndExit(m, msg.err)
		}
		// set the result and start the relock computation
		m.lockfileGraph = msg.resolvedGraph
		m.lockfilePatches = msg.allPatches
		if m.options.Manifest != "" {
			cmds = append(cmds, doInitialRelockCmd(m.options, m.manifestRW))
		} else {
			m.st = newStateChooseStrategy(m)
			cmds = append(cmds, m.st.Init(m))
		}

	// relocking finished
	case doRelockMsg:
		if msg.err != nil {
			return errorAndExit(m, msg.err)
		}
		// set the result and go to next state
		m.relockBaseManifest = msg.resolvedManifest
		m.relockBaseErrors = computeResolveErrors(msg.resolvedManifest.Graph)
		if m.options.Lockfile == "" {
			m.st = stateRelockResult{}
		} else {
			m.st = newStateChooseStrategy(m)
		}
		cmds = append(cmds, m.st.Init(m))
	}

	return m, tea.Batch(cmds...)
}

func (s stateInitialize) View(m Model) string {
	sb := strings.Builder{}
	if m.options.Lockfile == "" {
		sb.WriteString("No lockfile provided. Assuming re-lock.\n")
	} else {
		fmt.Fprintf(&sb, "Scanning %s ", components.SelectedTextStyle.Render(m.options.Lockfile))
		if m.lockfileGraph.Graph == nil {
			sb.WriteString(s.spinner.View())
			sb.WriteString("\n")

			return sb.String()
		}
		sb.WriteString("✓\n")
	}

	fmt.Fprintf(&sb, "Resolving %s ", components.SelectedTextStyle.Render(m.options.Manifest))
	if m.relockBaseManifest == nil {
		sb.WriteString(s.spinner.View())
		sb.WriteString("\n")
	} else {
		sb.WriteString("✓\n")
	}

	return sb.String()
}

func (s stateInitialize) InfoView() string               { return "" }
func (s stateInitialize) Resize(_, _ int) modelState     { return s }
func (s stateInitialize) ResizeInfo(_, _ int) modelState { return s }
func (s stateInitialize) IsInfoFocused() bool            { return false }

type inPlaceResolutionMsg struct {
	resolvedGraph remediation.ResolvedGraph
	allPatches    []result.Patch
	err           error
}

func doInPlaceResolutionCmd(opts options.FixVulnsOptions, rw lockfile.ReadWriter) tea.Cmd {
	return func() tea.Msg {
		g, err := parser.ParseLockfile(opts.Lockfile, rw)
		if err != nil {
			return inPlaceResolutionMsg{err: err}
		}

		resolved, err := remediation.ResolveGraphVulns(context.Background(), opts.ResolveClient, opts.VulnEnricher, g, nil, &opts.RemediationOptions)
		if err != nil {
			return inPlaceResolutionMsg{err: fmt.Errorf("failed resolving lockfile vulnerabilities: %w", err)}
		}
		allPatches, err := inplace.ComputePatches(context.Background(), opts.ResolveClient, resolved, &opts.RemediationOptions)
		if err != nil {
			return inPlaceResolutionMsg{err: fmt.Errorf("failed computing patches: %w", err)}
		}
		return inPlaceResolutionMsg{resolvedGraph: resolved, allPatches: allPatches}
	}
}

type doRelockMsg struct {
	resolvedManifest *remediation.ResolvedManifest
	err              error
}

func doInitialRelockCmd(opts options.FixVulnsOptions, rw manifest.ReadWriter) tea.Cmd {
	return func() tea.Msg {
		m, err := parser.ParseManifest(opts.Manifest, rw)
		if err != nil {
			return doRelockMsg{err: err}
		}
		if opts.DepCachePopulator != nil {
			opts.DepCachePopulator.PopulateCache(context.Background(), opts.ResolveClient, m.Requirements(), opts.Manifest)
		}
		resolved, err := remediation.ResolveManifest(context.Background(), opts.ResolveClient, opts.VulnEnricher, m, &opts.RemediationOptions)
		if err != nil {
			return doRelockMsg{err: fmt.Errorf("failed resolving manifest vulnerabilities: %w", err)}
		}
		return doRelockMsg{resolvedManifest: resolved}
	}
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
