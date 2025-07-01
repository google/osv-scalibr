// Package filter defines the interface to implement a unknown binary filter.
package filter

import (
	"context"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

// Filter is an interface for filtering out binaries that are known to be from an existing extracted source.
type Filter interface {
	// HashSetFilter removes binaries from the unknownBinariesSet that are found to be from a trusted source.
	HashSetFilter(ctx context.Context, fs scalibrfs.FS, unknownBinariesSet map[string]struct{}) error
	// ShouldExclude returns whether a given binary path should be excluded from the scan.
	ShouldExclude(ctx context.Context, fs scalibrfs.FS, binaryPath string) bool
	// Name returns the name of the filter.
	Name() string
}
