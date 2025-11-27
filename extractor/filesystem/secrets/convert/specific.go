package convert

import (
	"context"
	"fmt"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/veles"
)

// FromVelesDetectorWithRequire converts a Veles Detector into a SCALIBR FilesystemExtractor plugin.
// This allows:
// - Enabling Veles Detectors individually like regular SCALIBR plugins.
// - Using the provided detector in the detection engine with other detectors.
// - Using the detector as a standalone filesystem extractor.
func FromVelesDetectorWithRequire(velesDetector veles.Detector, name string, version int, fileRequired func(filesystem.FileAPI) bool) filesystem.Extractor {
	return &withRequire{
		velesDetector: velesDetector,
		name:          name,
		version:       version,
		fileRequired:  fileRequired,
	}
}

// withRequire is a wrapper around the veles.Detector interface that
// implements the additional functions of the filesystem Extractor interface.
type withRequire struct {
	velesDetector veles.Detector
	name          string
	version       int
	fileRequired  func(filesystem.FileAPI) bool
	e             *veles.DetectionEngine
}

// MaxSecretLen returns the maximum length a secret from this Detector can have.
func (w *withRequire) MaxSecretLen() uint32 {
	return w.velesDetector.MaxSecretLen()
}

// Detect finds candidate secrets in the data and returns them alongside their
// starting positions.
func (w *withRequire) Detect(data []byte) ([]veles.Secret, []int) {
	return w.velesDetector.Detect(data)
}

// Name of the secret extractor.
func (w *withRequire) Name() string {
	return w.name
}

// Version of the secret extractor.
func (w *withRequire) Version() int {
	return w.version
}

// Requirements of the secret extractor.
func (w *withRequire) Requirements() *plugin.Capabilities {
	// Veles plugins don't have any special requirements.
	return &plugin.Capabilities{}
}

// FileRequired returns the provided file required callback.
func (w *withRequire) FileRequired(api filesystem.FileAPI) bool {
	return w.fileRequired(api)
}

// IsRequirer implements the requirer interface.
func (w *withRequire) IsRequirer() bool {
	return true
}

// Extract extracts secret from the filesystem using the provided detector.
func (w *withRequire) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if w.e == nil {
		var err error
		w.e, err = veles.NewDetectionEngine([]veles.Detector{w.velesDetector})
		if err != nil {
			return inventory.Inventory{}, err
		}
	}
	secrets, err := w.e.Detect(ctx, input.Reader)
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
