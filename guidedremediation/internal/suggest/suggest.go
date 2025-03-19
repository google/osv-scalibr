package suggest

import (
	"context"
	"errors"
	"fmt"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/result"
)

// A PatchSuggester provides an ecosystem-specific method for 'suggesting'
// Patch for dependency updates.
type PatchSuggester interface {
	// Suggest returns the Patch required to update the dependencies to
	// a newer version based on the given options.
	Suggest(ctx context.Context, mf manifest.Manifest, opts options.UpdateOptions) (result.Patch, error)
}

func GetSuggester(system resolve.System) (PatchSuggester, error) {
	switch system {
	case resolve.Maven:
		return &MavenSuggester{}, nil
	case resolve.NPM:
		return nil, errors.New("npm not yet supported")
	case resolve.PyPI:
		return nil, errors.New("PyPI not yet supported")
	case resolve.UnknownSystem:
		return nil, errors.New("unknown system")
	default:
		return nil, fmt.Errorf("unsupported ecosystem: %v", system)
	}
}
