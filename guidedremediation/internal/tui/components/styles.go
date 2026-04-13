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

package components

import "github.com/charmbracelet/lipgloss"

var (
	// ColorPrimary is the primary highlight color.
	ColorPrimary = lipgloss.Color("#e62129") // Red, from the OSV logo
	// ColorDisabled is the color for disabled text.
	ColorDisabled = lipgloss.AdaptiveColor{Light: "250", Dark: "238"} // Grey
	// SelectedTextStyle is the style for selected text.
	SelectedTextStyle = lipgloss.NewStyle().Foreground(ColorPrimary)
	// DisabledTextStyle is the style for disabled text.
	DisabledTextStyle = lipgloss.NewStyle().Foreground(ColorDisabled)
)

// View dimensions
// width / height refers to the internal text area of the view
// i.e. excluding the border and the padding
const (
	ViewMinHeight = 20 // the minimum internal height the view can be
	ViewVPad      = 1  // the vertical padding of the view

	ViewMinWidth = 60  // the minimum internal width the view can be
	ViewWidthPct = 0.4 // percentage of terminal internal width the main view should occupy
	ViewHPad     = 2   // the horizontal padding of the view
)
