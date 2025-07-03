// Package unknownbinariesextr identifies binary files on the filesystem and adds them as packages.
package unknownbinariesextr

import (
	"context"
	"regexp"

	//nolint:gosec //md5 used to identify files, not for security purposes
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

var (
	// Common binary / executable file extensions
	fileExts = []string{
		".a",
		// Binary extensions
		".bin",
		".elf",
		".run",
		".o",

		// Shared library extension
		".so",
		// and .so.[number]

		// Script extensions
		".py", // Python
		".sh", // bash/sh/zsh
		".bash",

		".pl",  // Perl
		".rb",  // Ruby
		".php", // Php
		".awk", // Awk
		".tcl", // tcl
	}
	fileExtRegexes = map[string]*regexp.Regexp{
		".so.": regexp.MustCompile(`.so.\d+$`),
	}
)

const (
	// Name is the unique name of this extractor.
	Name = "ffa/unknownbinaries"
)

// Extractor finds unknown binaries on the filesystem
type Extractor struct {
}

// Name of the extractor.
func (e *Extractor) Name() string { return Name }

// Version of the extractor.
func (e *Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e *Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		OS: plugin.OSUnix,
	}
}

// FileRequired returns true for likely directories to contain vendored c/c++ code
func (e *Extractor) FileRequired(fapi filesystem.FileAPI) bool {
	return filesystem.IsInterestingExecutable(fapi)
}

// Extract determines the most likely package version from the directory and returns them as
// package entries with "Location" filled in.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	// TODO: If target file is a symlink, we should store the symlink target as a unknown binary

	return inventory.Inventory{
		Packages: []*extractor.Package{
			{
				Locations: []string{input.Path},
			},
		}}, nil
}

var _ filesystem.Extractor = &Extractor{}
