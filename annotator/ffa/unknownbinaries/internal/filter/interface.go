package filter

import (
	"context"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

type Filter interface {
	HashSetFilter(ctx context.Context, fs scalibrfs.FS, unknownBinariesSet map[string]struct{}) error
	ShouldExclude(ctx context.Context, fs scalibrfs.FS, binaryPath string) bool
	Name() string
}
