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

// Package model provides the program model for the guided remediation interactive tui.
package model

import (
	"os"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/osv-scalibr/guidedremediation/internal/lockfile"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/internal/remediation"
	"github.com/google/osv-scalibr/guidedremediation/internal/tui/components"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/log"
	"golang.org/x/term"
)

// Model is a bubbletea Model for the guided remediation interactive tui.
type Model struct {
	manifestRW manifest.ReadWriter
	lockfileRW lockfile.ReadWriter
	options    options.FixVulnsOptions

	lockfileGraph   remediation.ResolvedGraph
	lockfilePatches []result.Patch

	relockBaseManifest *remediation.ResolvedManifest
	relockBaseErrors   []result.ResolveError

	termWidth  int // width of the whole terminal
	termHeight int // height of the whole terminal

	viewWidth       int                        // width of each of the two view panel
	viewHeight      int                        // height of each of the two view panel
	viewStyle       lipgloss.Style             // border style to render views
	detailsRenderer components.DetailsRenderer // renderer for markdown details.

	help help.Model // help text renderer

	st      modelState // current state of program
	err     error      // set if a fatal error occurs within the program
	writing bool       // whether the model is currently shelling out writing lockfile/manifest file
}

// NewModel creates a new Model for the guided remediation interactive tui.
func NewModel(manifestRW manifest.ReadWriter, lockfileRW lockfile.ReadWriter, opts options.FixVulnsOptions, detailsRenderer components.DetailsRenderer) (Model, error) {
	if detailsRenderer == nil {
		detailsRenderer = components.FallbackDetailsRenderer{}
	}
	m := Model{
		manifestRW: manifestRW,
		lockfileRW: lockfileRW,
		options:    opts,
		st:         newStateInitialize(),
		help:       help.New(),
		viewStyle: lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			Padding(components.ViewVPad, components.ViewHPad),
		detailsRenderer: detailsRenderer,
	}

	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		log.Errorf("Failed to get terminal size: %v", err)
		return Model{}, err
	}
	m = m.setTermSize(w, h)

	return m, nil
}

func (m Model) setTermSize(w, h int) Model {
	m.termWidth = w
	m.termHeight = h

	// The internal rendering space of the views occupy a percentage of the terminal width
	viewWidth := max(int(float64(w)*components.ViewWidthPct), components.ViewMinWidth)
	// The internal height is constant
	viewHeight := components.ViewMinHeight

	// The total width/height, including the whitespace padding and border characters on each side
	paddedWidth := viewWidth + 2*components.ViewHPad + 2
	paddedHeight := viewHeight + 2*components.ViewVPad + 2

	// resize the views to the calculated dimensions
	m.viewWidth = viewWidth
	m.viewHeight = viewHeight
	m.viewStyle = m.viewStyle.Width(paddedWidth).Height(paddedHeight)

	m.st = m.st.ResizeInfo(m.viewWidth, m.viewHeight)

	return m
}

func (m Model) getBorderStyles() (lipgloss.Style, lipgloss.Style) {
	unfocused := m.viewStyle.BorderForeground(components.ColorDisabled)
	if m.st.IsInfoFocused() {
		return unfocused, m.viewStyle
	}
	return m.viewStyle, unfocused
}

func errorAndExit(m Model, err error) (tea.Model, tea.Cmd) {
	m.err = err
	return m, tea.Quit
}

// Init initializes the model.
func (m Model) Init() tea.Cmd {
	return m.st.Init(m)
}

// Update updates the model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case msg.Type == tea.KeyCtrlC: // always quit on ctrl+c
			return m, tea.Quit
		case key.Matches(msg, components.Keys.Help): // toggle help
			m.help.ShowAll = !m.help.ShowAll
		}
	case tea.WindowSizeMsg:
		m = m.setTermSize(msg.Width, msg.Height)
	}

	return m.st.Update(m, msg)
}

// View returns the view of the model.
func (m Model) View() string {
	// render both views side-by-side
	mainStyle, infoStyle := m.getBorderStyles()
	mainView := mainStyle.Render(m.st.View(m))
	infoView := infoStyle.Render(m.st.InfoView())
	view := lipgloss.JoinHorizontal(lipgloss.Top, mainView, infoView)

	// If we can't fit both side-by-side, only render the focused view
	if lipgloss.Width(view) > m.termWidth {
		if m.st.IsInfoFocused() {
			view = infoView
		} else {
			view = mainView
		}
	}

	// add the help to the bottom
	view = lipgloss.JoinVertical(lipgloss.Center, view, m.help.View(components.Keys))

	return lipgloss.Place(m.termWidth, m.termHeight, lipgloss.Center, lipgloss.Center, view)
}

// Error returns the error of the model, if any.
func (m Model) Error() error {
	return m.err
}

type modelState interface {
	Init(m Model) tea.Cmd
	Update(m Model, msg tea.Msg) (tea.Model, tea.Cmd)
	View(m Model) string
	Resize(w, h int) modelState

	InfoView() string
	ResizeInfo(w, h int) modelState
	IsInfoFocused() bool
}

type writeMsg struct {
	err error
}
