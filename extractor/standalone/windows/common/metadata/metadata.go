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

// Package metadata provides metadata structures to annotate Windows packages.
package metadata

// OSVersion provides metadata about the OS version.
type OSVersion struct {
	// Product name of the OS, e.g. "windows_server_2019".
	Product string
	// FullVersion is the full version of the OS version: Major.Minor.Build.Revision.
	FullVersion string
}

// WingetPackage provides metadata about a package installed via Windows Package Manager.
type WingetPackage struct {
	// Name is the display name of the package.
	Name string
	// ID is the unique package identifier.
	ID string
	// Version is the installed version.
	Version string
	// Moniker is the short name/alias for the package.
	Moniker string
	// Channel is the release channel.
	Channel string
	// Tags are package categories/tags.
	Tags []string
	// Commands are executable commands provided by the package.
	Commands []string
}
