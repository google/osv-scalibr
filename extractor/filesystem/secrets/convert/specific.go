package convert

import (
	"context"
	"fmt"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/veles"
)

// FromVelesDetectorWithRequire works similar to FromVelesDetector but allows specifying additional files to look at on top of the default ones.
func FromVelesDetectorWithRequire(velesDetector veles.Detector, name string, version int, fileRequired func(filesystem.FileAPI) bool) filesystem.Extractor {
	return &detectorWithRequire{
		velesDetector: velesDetector,
		name:          name,
		version:       version,
		fileRequired:  fileRequired,
	}
}

// extractorKeeper signals that a Detector also functions as a standalone filesystem.Extractor.
type extractorKeeper interface {
	KeepExtractor() bool
}

// Assert that detectorWithRequire implements the required interfaces.
var _ veles.Detector = &detectorWithRequire{}
var _ filesystem.Extractor = &detectorWithRequire{}
var _ extractorKeeper = &detectorWithRequire{}

// detectorWithRequire is a wrapper around the veles.Detector interface that
// implements the additional functions of the filesystem Extractor interface.
type detectorWithRequire struct {
	velesDetector veles.Detector
	name          string
	version       int
	fileRequired  func(filesystem.FileAPI) bool
	e             *veles.DetectionEngine
}

// KeepExtractor signals that this detector must also be registered as a standalone
// filesystem.Extractor to handle the additional files specified in the fileRequired callback.
func (d *detectorWithRequire) KeepExtractor() bool { return true }

// MaxSecretLen returns the maximum length a secret from this Detector can have.
func (d *detectorWithRequire) MaxSecretLen() uint32 {
	return d.velesDetector.MaxSecretLen()
}

// Detect finds candidate secrets in the data and returns them alongside their
// starting positions.
func (d *detectorWithRequire) Detect(data []byte) ([]veles.Secret, []int) {
	return d.velesDetector.Detect(data)
}

// Name of the secret extractor.
func (d *detectorWithRequire) Name() string {
	return d.name
}

// Version of the secret extractor.
func (d *detectorWithRequire) Version() int {
	return d.version
}

// Requirements of the secret extractor.
func (d *detectorWithRequire) Requirements() *plugin.Capabilities {
	// Veles plugins don't have any special requirements.
	return &plugin.Capabilities{}
}

// FileRequired returns the provided file required callback.
func (d *detectorWithRequire) FileRequired(api filesystem.FileAPI) bool {
	return d.fileRequired(api)
}

// Extract extracts secret from the filesystem using the provided detector.
func (d *detectorWithRequire) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if d.e == nil {
		var err error
		d.e, err = veles.NewDetectionEngine([]veles.Detector{d.velesDetector})
		if err != nil {
			return inventory.Inventory{}, err
		}
	}
	secrets, err := d.e.Detect(ctx, input.Reader)
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
