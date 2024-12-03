// Copyright 2024 Google LLC
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

// Package image provides functionality to scan a container image by layers for software
// inventory.
package image

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"archive/tar"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	scalibrImage "github.com/google/osv-scalibr/artifact/image"
	"github.com/google/osv-scalibr/artifact/image/pathtree"
	"github.com/google/osv-scalibr/artifact/image/whiteout"
)

const (
	// DefaultMaxFileBytes is the default maximum size of files that will be unpacked. Larger files are ignored.
	// The max is large because some files are hundreds of megabytes.
	DefaultMaxFileBytes = 1024 * 1024 * 1024 // 1GB
)

var (
	// ErrFileReadLimitExceeded is returned when a file exceeds the read limit. This is intended to
	// prevent zip bomb attacks, for example.
	ErrFileReadLimitExceeded = errors.New("file exceeds read limit")
)

// ========================================================
// IMAGE TYPES AND METHODS
// ========================================================

// Config contains the configuration to load an Image.
type Config struct {
	MaxFileBytes int64
}

// DefaultConfig returns the default configuration to load an Image.
func DefaultConfig() *Config {
	return &Config{
		MaxFileBytes: DefaultMaxFileBytes,
	}
}

// Image is a container image. It is composed of a set of layers that can be scanned for software
// inventory. It contains the proper metadata to attribute inventory to layers.
type Image struct {
	chainLayers    []*chainLayer
	maxFileBytes   int64
	ExtractDir     string
	BaseImageIndex int
}

// ChainLayers returns the chain layers of the image.
func (img *Image) ChainLayers() ([]scalibrImage.ChainLayer, error) {
	scalibrChainLayers := make([]scalibrImage.ChainLayer, 0, len(img.chainLayers))
	for _, chainLayer := range img.chainLayers {
		scalibrChainLayers = append(scalibrChainLayers, chainLayer)
	}
	return scalibrChainLayers, nil
}

// CleanUp removes the temporary directory used to store the image files.
func (img *Image) CleanUp() error {
	return os.RemoveAll(img.ExtractDir)
}

// FromRemoteName creates an Image from a remote container image name.
func FromRemoteName(imageName string, config *Config, imageOptions ...remote.Option) (*Image, error) {
	v1Image, err := scalibrImage.V1ImageFromRemoteName(imageName, imageOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to load image from remote name %q: %w", imageName, err)
	}
	return FromV1Image(v1Image, config)
}

// FromTarball creates an Image from a tarball file that stores a container image.
func FromTarball(tarPath string, config *Config) (*Image, error) {
	v1Image, err := tarball.ImageFromPath(tarPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load image from tarball with path %q: %w", tarPath, err)
	}
	return FromV1Image(v1Image, config)
}

// FromV1Image takes a v1.Image and produces a layer-scannable Image. The steps taken are as
// follows:
//
//		(1) Retrieves v1.Layers, configFile. Creates tempPath to store the image files.
//		(2) Initializes the output image and the chain layers.
//		(3) Unpacks the layers by looping through the layers in reverse, while filling in the files
//	      into the appropriate chain layer.
func FromV1Image(v1Image v1.Image, config *Config) (*Image, error) {
	configFile, err := v1Image.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("failed to load config file: %w", err)
	}

	v1Layers, err := v1Image.Layers()
	if err != nil {
		return nil, fmt.Errorf("failed to load layers: %w", err)
	}

	chainLayers, err := initializeChainLayers(v1Layers, configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize chain layers: %w", err)
	}

	tempPath, err := os.MkdirTemp("", "osv-scalibr-image-scanning-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}

	baseImageIndex, err := findBaseImageIndex(configFile.History)
	if err != nil {
		baseImageIndex = -1
	}

	outputImage := Image{
		chainLayers:    chainLayers,
		ExtractDir:     tempPath,
		BaseImageIndex: baseImageIndex,
		maxFileBytes:   config.MaxFileBytes,
	}

	// Add the root directory to each chain layer. If this is not done, then the virtual paths won't
	// be rooted, and traversal in the virtual filesystem will be broken.
	for _, chainLayer := range chainLayers {
		err := chainLayer.fileNodeTree.Insert("/", &fileNode{
			extractDir:    outputImage.ExtractDir,
			originLayerID: chainLayer.latestLayer.DiffID(),
			virtualPath:   "/",
			isWhiteout:    false,
			mode:          fs.ModeDir,
		})

		if err != nil {
			return &outputImage, fmt.Errorf("failed to insert root node in path tree: %w", err)
		}
	}

	// Reverse loop through the layers to start from the latest layer first. This allows us to skip
	// all files already seen.
	for i := len(chainLayers) - 1; i >= 0; i-- {
		chainLayer := chainLayers[i]

		// If the layer is empty, then there is nothing to do.
		if chainLayer.latestLayer.IsEmpty() {
			continue
		}

		dirPath := path.Join(tempPath, chainLayer.latestLayer.DiffID())

		// TODO b/378491191 - Determine if an error should be thrown if the directory already exists. If
		// so, we can probably use os.MkdirAll instead.
		if err := os.Mkdir(dirPath, dirPermission); err != nil && !errors.Is(err, fs.ErrExist) {
			return &outputImage, fmt.Errorf("failed to create chain layer directory: %w", err)
		}

		chainLayersToFill := chainLayers[i:]
		originLayerID := chainLayer.latestLayer.DiffID()
		layerReader, err := chainLayer.latestLayer.Uncompressed()
		if err != nil {
			return &outputImage, err
		}

		err = func() error {
			// Manually close at the end of the for loop.
			defer layerReader.Close()

			tarReader := tar.NewReader(layerReader)
			if err := fillChainLayerWithFilesFromTar(&outputImage, tarReader, originLayerID, dirPath, chainLayersToFill); err != nil {
				return fmt.Errorf("failed to fill chain layer with v1 layer tar: %w", err)
			}
			return nil
		}()

		if err != nil {
			return &outputImage, err
		}
	}
	return &outputImage, nil
}

// ========================================================
// Helper functions
// ========================================================

// initializeChainLayers initializes the chain layers based on the config file history and the
// v1.Layers found in the image from the tarball.
func initializeChainLayers(v1Layers []v1.Layer, configFile *v1.ConfigFile) ([]*chainLayer, error) {
	layerIndex := 0
	chainLayers := make([]*chainLayer, 0, len(configFile.History))
	for _, entry := range configFile.History {
		if entry.EmptyLayer {
			chainLayers = append(chainLayers, &chainLayer{
				fileNodeTree: pathtree.NewNode[fileNode](),
				index:        layerIndex,
				latestLayer: &Layer{
					buildCommand: entry.CreatedBy,
					isEmpty:      true,
				},
			})
			continue
		}

		if layerIndex >= len(v1Layers) {
			return nil, fmt.Errorf("config history contains more non-empty layers than expected (%d)", len(v1Layers))
		}

		nextNonEmptyLayer := v1Layers[layerIndex]
		layer, err := convertV1Layer(nextNonEmptyLayer, entry.CreatedBy, false)
		if err != nil {
			return nil, err
		}

		chainLayer := &chainLayer{
			fileNodeTree: pathtree.NewNode[fileNode](),
			index:        layerIndex,
			latestLayer:  layer,
		}
		chainLayers = append(chainLayers, chainLayer)

		layerIndex++
	}

	for layerIndex < len(v1Layers) {
		layer, err := convertV1Layer(v1Layers[layerIndex], "", false)
		if err != nil {
			return nil, err
		}
		chainLayers = append(chainLayers, &chainLayer{
			fileNodeTree: pathtree.NewNode[fileNode](),
			index:        layerIndex,
			latestLayer:  layer,
		})
		layerIndex++
	}

	return chainLayers, nil
}

// fillChainLayerWithFilesFromTar fills the chain layers with the files found in the tar. The
// chainLayersToFill are the chain layers that will be filled with the files via the virtual
// filesystem.
func fillChainLayerWithFilesFromTar(img *Image, tarReader *tar.Reader, originLayerID string, dirPath string, chainLayersToFill []*chainLayer) error {
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("could not read tar: %w", err)
		}
		// Some tools prepend everything with "./", so if we don't Clean the
		// name, we may have duplicate entries, which angers tar-split.
		// Using path instead of filepath to keep `/` and deterministic behavior
		cleanedFilePath := path.Clean(header.Name)

		// Prevent "Zip Slip"
		if strings.HasPrefix(cleanedFilePath, "../") {
			continue
		}

		// Force PAX format to remove Name/Linkname length limit of 100 characters required by USTAR
		// and to not depend on internal tar package guess which prefers USTAR over PAX.
		header.Format = tar.FormatPAX

		// There is a difference between the filepath and path modules. The filepath module will handle
		// OS specific path separators, whereas the path module will not. This is important because
		// some operating systems (like Windows) do not use forward slashes as path separators.
		// The filepath module will be used to determine the real file path on disk, whereas path module
		// will be used for the virtual path.
		basename := filepath.Base(cleanedFilePath)
		dirname := filepath.Dir(cleanedFilePath)

		tombstone := strings.HasPrefix(basename, whiteout.WhiteoutPrefix)
		// TODO: b/379094217 - Handle Opaque Whiteouts
		if tombstone {
			basename = basename[len(whiteout.WhiteoutPrefix):]
		}

		// If we're checking a directory, don't filepath.Join names.
		var virtualPath string
		if header.Typeflag == tar.TypeDir {
			virtualPath = "/" + cleanedFilePath
		} else {
			virtualPath = "/" + path.Join(dirname, basename)
		}

		// realFilePath is where the file will be written to disk. filepath.Clean first to convert
		// to OS specific file path.
		// TODO: b/377553499 - Escape invalid characters on windows that's valid on linux
		realFilePath := filepath.Join(dirPath, filepath.Clean(cleanedFilePath))

		var fileMode fs.FileMode
		// Write out the file/dir to disk.
		switch header.Typeflag {
		case tar.TypeDir:
			fileMode, err = img.handleDir(realFilePath, tarReader, header)
			if err != nil {
				return fmt.Errorf("failed to handle directory: %w", err)
			}

		default:
			// TODO: b/374769529 - Handle symlinks.
			// Assume if it's not a directory, it's a normal file.
			fileMode, err = img.handleFile(realFilePath, tarReader, header)
			if err != nil {
				return fmt.Errorf("failed to handle file: %w", err)
			}
		}

		// In each outer loop, a layer is added to each relevant output chainLayer slice. Because the
		// outer loop is looping backwards (latest layer first), we ignore any files that are already in
		// each chainLayer, as they would have been overwritten.
		fillChainLayersWithVirtualPath(img, chainLayersToFill, originLayerID, virtualPath, tombstone, fileMode)
	}

	return nil
}

// handleDir creates the directory specified by path, if it doesn't exist.
func (img *Image) handleDir(path string, tarReader *tar.Reader, header *tar.Header) (fs.FileMode, error) {
	if _, err := os.Stat(path); err != nil {
		if err := os.MkdirAll(path, dirPermission); err != nil {
			return 0, fmt.Errorf("failed to create directory with path %s: %w", path, err)
		}
	}
	return fs.FileMode(header.Mode) | fs.ModeDir, nil
}

// handleFile creates the file specified by path, and then copies the contents of the tarReader into
// the file.
func (img *Image) handleFile(path string, tarReader *tar.Reader, header *tar.Header) (fs.FileMode, error) {
	// Write all files as read/writable by the current user, inaccessible by anyone else
	// Actual permission bits are stored in FileNode
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, filePermission)

	if err != nil {
		return 0, err
	}
	defer f.Close()

	numBytes, err := io.Copy(f, io.LimitReader(tarReader, img.maxFileBytes))
	if numBytes >= img.maxFileBytes || errors.Is(err, io.EOF) {
		return 0, ErrFileReadLimitExceeded
	}

	if err != nil {
		return 0, fmt.Errorf("unable to copy file: %w", err)
	}

	return fs.FileMode(header.Mode), nil
}

// fillChainLayersWithVirtualPath fills the chain layers with the virtual path.
func fillChainLayersWithVirtualPath(img *Image, chainLayers []*chainLayer, originLayerID, virtualPath string, isWhiteout bool, fileMode fs.FileMode) {
	for _, chainLayer := range chainLayers {
		if node := chainLayer.fileNodeTree.Get(virtualPath); node != nil {
			// A newer version of the file already exists on a later chainLayer.
			// Since we do not want to overwrite a later layer with information
			// written in an earlier layer, skip this file.
			continue
		}

		// check for a whited out parent directory
		if inWhiteoutDir(chainLayer, virtualPath) {
			// The entire directory has been deleted, so no need to save this file
			continue
		}

		// Add the file to the chain layer. If there is an error, then we fail open.
		// TODO: b/379154069 - Add logging for fail open errors.
		chainLayer.fileNodeTree.Insert(virtualPath, &fileNode{
			extractDir:    img.ExtractDir,
			originLayerID: originLayerID,
			virtualPath:   virtualPath,
			isWhiteout:    isWhiteout,
			mode:          fileMode,
		})
	}
}

// inWhiteoutDir returns whether the file is in a whiteout directory.
// TODO: b/379094217 - Verify that this works for opaque whiteouts.
func inWhiteoutDir(layer *chainLayer, filePath string) bool {
	for {
		if filePath == "" {
			break
		}
		dirname := filepath.Dir(filePath)
		if filePath == dirname {
			break
		}

		node := layer.fileNodeTree.Get(dirname)
		if node == nil {
			return false
		}
		if node.isWhiteout {
			return true
		}

		filePath = dirname
	}
	return false
}
