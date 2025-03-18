// fakelayerbuilder uses a yaml file with custom syntax to build up fake layers for testing
//
// Example:
//
// ```yml
//
// layers:
//
//	# Add foo.txt lockfile
//	- files:
//	    foo.txt:
//	    	# With the package foo
//	        - foo
//	    bar.txt:
//	        - bar
//	# Delete the bar lockfile
//	- files:
//	    !bar.txt:
//	- files:
//	    baz.txt:
//	        - baz
//	    # Readd bar
//	- files:
//	    bar.txt:
//	        - bar
//
// ```
package fakelayerbuilder

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/fakechainlayer"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/fakelayer"
	"github.com/google/osv-scalibr/artifact/image/whiteout"
	"github.com/opencontainers/go-digest"
	"gopkg.in/yaml.v3"
)

func parseFakeLayerFileFromPath(path string) (FakeTestLayers, error) {
	layers := FakeTestLayers{}

	data, err := os.ReadFile(path)
	if err != nil {
		return FakeTestLayers{}, err
	}

	err = yaml.Unmarshal(data, &layers)
	if err != nil {
		return FakeTestLayers{}, err
	}

	return layers, nil
}

func BuildFakeChainLayersFromPath(t *testing.T, testDir string, layerInfoPath string) []*fakechainlayer.FakeChainLayer {
	layers, err := parseFakeLayerFileFromPath(layerInfoPath)
	if err != nil {
		t.Fatalf("Failed to parse fake layer file %q: %q", layerInfoPath, err)
	}

	output := []*fakechainlayer.FakeChainLayer{}

	// chainLayerContents is edited every loop with the diffs of that layer
	chainLayerContents := map[string]string{}

	for index, layer := range layers.Layers {
		diffID := digest.NewDigestFromEncoded(digest.SHA256, fmt.Sprintf("diff-id-%d", index))
		command := fmt.Sprintf("command-%d", index)

		// Build and edit layer contents
		layerContents := map[string]string{}
		for key, file := range layer.Files {
			if strings.HasPrefix(key, "~") {
				key = strings.TrimPrefix(key, "~")
				layerContents[whiteout.ToWhiteout(key)] = ""
				delete(chainLayerContents, key)

				continue
			}
			layerContents[key] = strings.Join(file, "\n")
			chainLayerContents[key] = layerContents[key]
		}

		// Create fake layer and chainLayer
		fakeLayer, err := fakelayer.New(filepath.Join(testDir, fmt.Sprintf("layer-%d", index)), diffID, command, layerContents, false)
		if err != nil {
			t.Fatalf("fakelayer.New(%q, %q, %q, %v, %v) failed: %v", testDir, diffID, command, layerContents, false, err)
		}

		chainLayerContentsClone := make(map[string]string, len(chainLayerContents))
		for k, v := range chainLayerContents {
			chainLayerContentsClone[k] = v
		}
		chainLayer, err := fakechainlayer.New(filepath.Join(testDir, fmt.Sprintf("chainlayer-%d", index)), index, diffID, command, fakeLayer, chainLayerContentsClone, false)
		if err != nil {
			t.Fatalf("fakechainlayer.New(%d, %q, %q, %v, %v) failed: %v", index, diffID, command, layer, chainLayerContentsClone, err)
		}

		output = append(output, chainLayer)
	}

	return output
}
