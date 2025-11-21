package convert

import (
	"context"
	"fmt"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/veles"
)

type withRequire struct {
	engine *veles.DetectionEngine

	detectors []veles.Detector

	name         string
	version      int
	fileRequired func(api filesystem.FileAPI) bool
}

// Extract extracts secrets from a file using the specified detectors.
func (e *withRequire) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if e.engine == nil {
		var err error
		e.engine, err = veles.NewDetectionEngine(e.detectors)
		if err != nil {
			return inventory.Inventory{}, fmt.Errorf("error setting up the detection engine for %T: %w", e.detectors, err)
		}
	}
	secrets, err := e.engine.Detect(ctx, input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("unable to scan for secrets: %w", err)
	}
	i := inventory.Inventory{}
	for _, s := range secrets {
		i.Secrets = append(i.Secrets, &inventory.Secret{
			Secret:   s,
			Location: input.Path,
		})
	}
	return i, nil
}

// Name of the secret extractor.
func (e *withRequire) Name() string {
	return e.name
}

// Version of the secret extractor.
func (e *withRequire) Version() int {
	return e.version
}

// Requirements of the secret extractor.
func (e *withRequire) Requirements() *plugin.Capabilities {
	// Veles plugins don't have any special requirements.
	return &plugin.Capabilities{}
}

// FileRequired returns true if the file is required by the extractor.
func (e *withRequire) FileRequired(api filesystem.FileAPI) bool {
	return e.fileRequired(api)
}

// FromVelesDetectorWithRequire returns a filesystem extractor from a veles detector.
func FromVelesDetectorWithRequire(ds []veles.Detector, name string, version int, fileRequired func(api filesystem.FileAPI) bool) filesystem.Extractor {
	return &withRequire{
		detectors:    ds,
		name:         name,
		version:      version,
		fileRequired: fileRequired,
	}
}
