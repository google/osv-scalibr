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

// Package components contains some TUI components for the guided remediation interactive CLI.
package components

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// KeyMap holds the key bindings for the guided remediation interactive TUI.
type KeyMap struct {
	Up         key.Binding
	Down       key.Binding
	Left       key.Binding
	Right      key.Binding
	Select     key.Binding
	SwitchView key.Binding
	Help       key.Binding
	Quit       key.Binding
}

// ShortHelp returns the short help for the key map.
func (k KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Help, k.Quit}
}

// FullHelp returns the full help for the key map.
func (k KeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down},
		{k.Select, k.SwitchView},
		{k.Help, k.Quit},
	}
}

// Keys is the default key map for the guided remediation interactive TUI.
var Keys = KeyMap{
	Up: key.NewBinding(
		key.WithKeys("up"),
		key.WithHelp("↑", "move up"),
	),
	Down: key.NewBinding(
		key.WithKeys("down"),
		key.WithHelp("↓", "move down"),
	),
	Left: key.NewBinding(
		key.WithKeys("left"),
	),
	Right: key.NewBinding(
		key.WithKeys("right"),
	),
	Select: key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("enter", "select option"),
	),
	SwitchView: key.NewBinding(
		key.WithKeys("tab", "i"),
		key.WithHelp("i/tab", "switch views"),
	),
	Help: key.NewBinding(
		key.WithKeys("h"),
		key.WithHelp("h", "toggle help"),
	),
	Quit: key.NewBinding(
		key.WithKeys("q", "esc"),
		key.WithHelp("q/esc", "exit"),
	),
}

// NewSpinner creates a stylised spinner
func NewSpinner() spinner.Model {
	sp := spinner.New(spinner.WithSpinner(spinner.Line))
	// Spinner.FPS is actually the duration of each frame, not the frames per second
	sp.Spinner.FPS = 200 * time.Millisecond

	return sp
}

// RenderSelectorOption provides an inline selector renderer,
// for layouts that don't fit neatly into a list/table
func RenderSelectorOption(
	selected bool, // whether this line is currently highlighted
	cursor string, // the cursor to display before the line, if it's selected
	format string, // format string for the content. Should only use `%v` specifier
	args ...any, // args for the format string. These will be highlighted if the line is selected
) string {
	if !selected {
		cursor = strings.Repeat(" ", lipgloss.Width(cursor))
	} else {
		cursor = SelectedTextStyle.Render(cursor)
		for i := range args {
			args[i] = SelectedTextStyle.Render(fmt.Sprintf("%v", args[i]))
		}
	}

	return fmt.Sprintf(cursor+format, args...)
}

// ViewModel provides a tea-like model for representing the secondary info panel
// which allows for resizing
type ViewModel interface {
	Update(msg tea.Msg) (ViewModel, tea.Cmd)
	View() string
	Resize(w, h int) ViewModel
}

// ViewModelCloseMsg provides a message to close the ViewModel
type ViewModelCloseMsg struct{}

// CloseViewModel provides a tea command to close the ViewModel.
var CloseViewModel tea.Cmd = func() tea.Msg { return ViewModelCloseMsg{} }

// TextView is a ViewModel for showing non-interactive text.
type TextView string

// Update is a no-op for TextView.
func (t TextView) Update(tea.Msg) (ViewModel, tea.Cmd) { return t, nil }

// View returns the text as a string.
func (t TextView) View() string { return string(t) }

// Resize is a no-op for TextView.
func (t TextView) Resize(int, int) ViewModel { return t }
