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

// Package image provides functionality to scan a container image by layers for software
// inventory.
package image

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	scalibrImage "github.com/google/osv-scalibr/artifact/image"
	"github.com/google/osv-scalibr/artifact/image/pathtree"
	"github.com/google/osv-scalibr/artifact/image/require"
	"github.com/google/osv-scalibr/artifact/image/symlink"
	"github.com/google/osv-scalibr/artifact/image/whiteout"
	"github.com/google/osv-scalibr/log"
)

const (
	// DefaultMaxFileBytes is the default maximum size of files that will be unpacked. Larger files are ignored.
	// The max is large because some files are hundreds of megabytes.
	DefaultMaxFileBytes = 1024 * 1024 * 1024 // 1GB
	// DefaultMaxSymlinkDepth is the default maximum symlink depth.
	DefaultMaxSymlinkDepth = 6
)

var (
	// ErrFileReadLimitExceeded is returned when a file exceeds the read limit. This is intended to
	// prevent zip bomb attacks, for example.
	ErrFileReadLimitExceeded = errors.New("file exceeds read limit")
	// ErrSymlinkPointsOutsideRoot is returned when a symlink points outside the root.
	ErrSymlinkPointsOutsideRoot = errors.New("symlink points outside the root")
	// ErrInvalidConfig is returned when the image config is invalid.
	ErrInvalidConfig = errors.New("invalid image config")
)

// ========================================================
// IMAGE TYPES AND METHODS
// ========================================================

// Config contains the configuration to load an Image.
type Config struct {
	MaxFileBytes    int64
	MaxSymlinkDepth int
	Requirer        require.FileRequirer
}

// DefaultConfig returns the default configuration to load an Image.
func DefaultConfig() *Config {
	return &Config{
		MaxFileBytes:    DefaultMaxFileBytes,
		MaxSymlinkDepth: DefaultMaxSymlinkDepth,
		// All files are required by default.
		Requirer: &require.FileRequirerAll{},
	}
}

// validateConfig makes sure that the config values will not cause issues while extracting the
// image. Checks include:
//
//	(1) MaxFileBytes is positive.
//	(2) Requirer is not nil.
//	(3) MaxSymlinkDepth is non-negative.
func validateConfig(config *Config) error {
	if config.MaxFileBytes <= 0 {
		return fmt.Errorf("%w: max file bytes must be positive: %d", ErrInvalidConfig, config.MaxFileBytes)
	}
	if config.Requirer == nil {
		return fmt.Errorf("%w: requirer must be specified", ErrInvalidConfig)
	}
	if config.MaxSymlinkDepth < 0 {
		return fmt.Errorf("%w: max symlink depth must be non-negative: %d", ErrInvalidConfig, config.MaxSymlinkDepth)
	}

	return nil
}

// Image is a container image. It is composed of a set of layers that can be scanned for software
// inventory. It contains the proper metadata to attribute inventory to layers.
type Image struct {
	chainLayers    []*chainLayer
	config         *Config
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
	// TODO b/381251067: Look into supporting OCI images.
	v1Image, err := tarball.ImageFromPath(tarPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load image from tarball with path %q: %w", tarPath, err)
	}

	return FromV1Image(v1Image, config)
}

// FromV1Image takes a v1.Image and produces a layer-scannable Image. The steps taken are as
// follows:
//
//		(1) Validates the user input image config object.
//		(2) Retrieves v1.Layers, configFile. Creates tempPath to store the image files.
//		(3) Initializes the output image and the chain layers.
//		(4) Unpacks the layers by looping through the layers in reverse, while filling in the files
//	      into the appropriate chain layer.
func FromV1Image(v1Image v1.Image, config *Config) (*Image, error) {
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid image config: %w", err)
	}

	configFile, err := v1Image.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("failed to load config file: %w", err)
	}

	v1Layers, err := v1Image.Layers()
	if err != nil {
		return nil, fmt.Errorf("failed to load layers: %w", err)
	}

	chainLayers, err := initializeChainLayers(v1Layers, configFile, config.MaxSymlinkDepth)
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
		config:         config,
		ExtractDir:     tempPath,
		BaseImageIndex: baseImageIndex,
	}

	// Add the root directory to each chain layer. If this is not done, then the virtual paths won't
	// be rooted, and traversal in the virtual filesystem will be broken.
	for _, chainLayer := range chainLayers {
		var layerDigest string
		if chainLayer.latestLayer.IsEmpty() {
			layerDigest = ""
		} else {
			layerDigest = chainLayer.latestLayer.DiffID().Encoded()
		}

		err := chainLayer.fileNodeTree.Insert("/", &fileNode{
			extractDir:    outputImage.ExtractDir,
			originLayerID: layerDigest,
			virtualPath:   "/",
			isWhiteout:    false,
			mode:          fs.ModeDir,
		})

		if err != nil {
			return &outputImage, fmt.Errorf("failed to insert root node in path tree: %w", err)
		}
	}

	// The number of passes through the layers is the max symlink depth + 1. The additional pass (+1)
	// is due to the fact that the regular file contents should always be extracted.
	totalPasses := config.MaxSymlinkDepth + 1
	requiredTargets := make(map[string]bool)

	for range totalPasses {
		// Reverse loop through the layers to start from the latest layer first. This allows us to skip
		// all files already seen.
		for i := len(chainLayers) - 1; i >= 0; i-- {
			chainLayer := chainLayers[i]

			// If the layer is empty, then there is nothing to do.
			if chainLayer.latestLayer.IsEmpty() {
				continue
			}

			originLayerID := chainLayer.latestLayer.DiffID().Encoded()

			// Create the chain layer directory if it doesn't exist.
			// Use filepath here as it is a path that will be written to disk.
			dirPath := filepath.Join(tempPath, originLayerID)
			if err := os.Mkdir(dirPath, dirPermission); err != nil && !errors.Is(err, fs.ErrExist) {
				return &outputImage, fmt.Errorf("failed to create chain layer directory: %w", err)
			}

			chainLayersToFill := chainLayers[i:]
			layerReader, err := chainLayer.latestLayer.Uncompressed()
			if err != nil {
				return &outputImage, err
			}

			err = func() error {
				// Manually close at the end of the for loop.
				defer layerReader.Close()

				tarReader := tar.NewReader(layerReader)
				requiredTargets, err = fillChainLayersWithFilesFromTar(&outputImage, tarReader, originLayerID, dirPath, chainLayersToFill, config.Requirer, requiredTargets)
				if err != nil {
					return fmt.Errorf("failed to fill chain layer with v1 layer tar: %w", err)
				}

				return nil
			}()

			if err != nil {
				return &outputImage, err
			}
		}

		// If there are no more required targets from symlinks, then there is no need to continue.
		if len(requiredTargets) == 0 {
			break
		}

		stillHaveRequiredTargets := false
		for _, isRequired := range requiredTargets {
			if isRequired {
				stillHaveRequiredTargets = true

				break
			}
		}

		if !stillHaveRequiredTargets {
			break
		}
	}

	return &outputImage, nil
}

// ========================================================
// Helper functions
// ========================================================

// initializeChainLayers initializes the chain layers based on the config file history, the
// v1.Layers found in the image from the tarball, and the max symlink depth.
func initializeChainLayers(v1Layers []v1.Layer, configFile *v1.ConfigFile, maxSymlinkDepth int) ([]*chainLayer, error) {
	if configFile == nil {
		return nil, fmt.Errorf("config file is nil")
	}

	var chainLayers []*chainLayer
	// v1LayerIndex tracks the next v1.Layer that should populated in a chain layer. This does not
	// include empty layers.
	v1LayerIndex := 0
	// historyIndex tracks the chain layer index including empty layers.
	historyIndex := 0

	// First loop through the history entries found in the config file. If the entry is an empty
	// layer, then create an empty chain layer. Otherwise, convert the v1.Layer to a scalibr Layer
	// and create a chain layer with it.
	for _, entry := range configFile.History {
		if entry.EmptyLayer {
			chainLayers = append(chainLayers, &chainLayer{
				fileNodeTree: pathtree.NewNode[fileNode](),
				index:        historyIndex,
				latestLayer: &Layer{
					buildCommand: entry.CreatedBy,
					isEmpty:      true,
					fileNodeTree: pathtree.NewNode[fileNode](),
				},
				maxSymlinkDepth: maxSymlinkDepth,
			})
			historyIndex++

			continue
		}

		if v1LayerIndex >= len(v1Layers) {
			return nil, fmt.Errorf("config history contains more non-empty layers than expected (%d)", len(v1Layers))
		}

		nextNonEmptyLayer := v1Layers[v1LayerIndex]
		layer, err := convertV1Layer(nextNonEmptyLayer, entry.CreatedBy, false)
		if err != nil {
			return nil, err
		}

		chainLayer := &chainLayer{
			fileNodeTree:    pathtree.NewNode[fileNode](),
			index:           historyIndex,
			latestLayer:     layer,
			maxSymlinkDepth: maxSymlinkDepth,
		}
		chainLayers = append(chainLayers, chainLayer)

		historyIndex++
		v1LayerIndex++
	}

	// If there are any remaining v1.Layers, then the history in the config file is missing entries.
	// This can happen depending on the build process used to create an image.
	for v1LayerIndex < len(v1Layers) {
		layer, err := convertV1Layer(v1Layers[v1LayerIndex], "", false)
		if err != nil {
			return nil, err
		}
		chainLayers = append(chainLayers, &chainLayer{
			fileNodeTree:    pathtree.NewNode[fileNode](),
			index:           historyIndex,
			latestLayer:     layer,
			maxSymlinkDepth: maxSymlinkDepth,
		})
		v1LayerIndex++
		historyIndex++
	}

	return chainLayers, nil
}

// fillChainLayersWithFilesFromTar fills the chain layers with the files found in the tar. The
// chainLayersToFill are the chain layers that will be filled with the files via the virtual
// filesystem.
func fillChainLayersWithFilesFromTar(img *Image, tarReader *tar.Reader, originLayerID string, dirPath string, chainLayersToFill []*chainLayer, requirer require.FileRequirer, requiredTargets map[string]bool) (map[string]bool, error) {
	currentChainLayer := chainLayersToFill[0]

	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("could not read tar: %w", err)
		}
		// Some tools prepend everything with "./", so if we don't path.Clean the name, we may have
		// duplicate entries, which angers tar-split. Using path instead of filepath to keep `/` and
		// deterministic behavior.
		cleanedFilePath := path.Clean(filepath.ToSlash(header.Name))

		// Prevent "Zip Slip"
		if strings.HasPrefix(cleanedFilePath, "../") {
			continue
		}

		// Force PAX format to remove Name/Linkname length limit of 100 characters required by USTAR and
		//  to not depend on internal tar package guess which prefers USTAR over PAX.
		header.Format = tar.FormatPAX

		// There is a difference between the filepath and path modules. The filepath module will handle
		// OS specific path separators, whereas the path module will not. This is important because
		// some operating systems (like Windows) do not use forward slashes as path separators.
		// The filepath module will be used to determine the real file path on disk, whereas path module
		// will be used for the virtual path.
		//
		// Generally, we want to use path over filepath, as forward slashes can be converted to backslashes
		// with any filepath operation, but this is not the case the other way, as backslashes are a valid
		// filename character.
		//
		// We use path here as both of these paths will be used as part of virtual paths.
		basename := path.Base(cleanedFilePath)
		dirname := path.Dir(cleanedFilePath)

		// If the base name is "." or "..", then skip it. For example, if the cleaned file path is
		// "/foo/bar/.", then we should skip it since it references "/foo/bar".
		if basename == "." || basename == ".." {
			continue
		}

		// Check if the file is a whiteout.
		isWhiteout := whiteout.IsWhiteout(basename)
		// TODO: b/379094217 - Handle Opaque Whiteouts
		if isWhiteout {
			basename = whiteout.ToPath(basename)
		}

		// If we're checking a directory, don't filepath.Join names.
		var virtualPath string
		if header.Typeflag == tar.TypeDir {
			virtualPath = "/" + cleanedFilePath
		} else {
			virtualPath = "/" + path.Join(dirname, basename)
		}

		// realFilePath is where the file will be written to disk. filepath.Join will convert
		// any forward slashes to the appropriate OS specific path separator.
		realFilePath := filepath.Join(dirPath, filepath.FromSlash(cleanedFilePath))

		// If the file already exists in the current chain layer, then skip it. This is done because
		// the tar file could be read multiple times to handle required symlinks.
		if currentChainLayer.fileNodeTree.Get(virtualPath) != nil {
			continue
		}

		// Skip files that are not required by extractors and are not targets of required symlinks.
		// Try multiple paths variations
		// (with parent dir, without leading slash, with leading slash). For example:
		// - `realFilePath`: `tmp/12345/etc/os-release`. This is used when actually writing the file to disk.
		// - `cleanedFilePath`: `etc/os-release`. This is used when checking if the file is required.
		// - `virtualPath`: `/etc/os-release`. This is used when checking if the file is required.
		required := false
		for _, p := range []string{realFilePath, cleanedFilePath, virtualPath} {
			if requirer.FileRequired(p, header.FileInfo()) {
				required = true

				break
			}
			if _, ok := requiredTargets[p]; ok {
				required = true

				// The required target has been checked, so it can be marked as not required.
				requiredTargets[p] = false

				break
			}
		}
		// If the header represents a directory, then it should be required in order to capture the
		// directory information, even if its filepath is not required.
		if !required && (header.Typeflag != tar.TypeDir) {
			continue
		}

		var newNode *fileNode
		switch header.Typeflag {
		case tar.TypeDir:
			newNode, err = img.handleDir(realFilePath, virtualPath, originLayerID, tarReader, header, isWhiteout)
		case tar.TypeReg:
			newNode, err = img.handleFile(realFilePath, virtualPath, originLayerID, tarReader, header, isWhiteout)
		case tar.TypeSymlink, tar.TypeLink:
			newNode, err = img.handleSymlink(virtualPath, originLayerID, tarReader, header, isWhiteout, requiredTargets)
		default:
			log.Warnf("unsupported file type: %v, path: %s", header.Typeflag, header.Name)

			continue
		}

		if err != nil {
			if errors.Is(err, ErrFileReadLimitExceeded) {
				log.Warnf("failed to handle tar entry with path %s: %w", virtualPath, err)

				continue
			}

			return nil, fmt.Errorf("failed to handle tar entry with path %s: %w", virtualPath, err)
		}

		// If the virtual path has any directories and those directories have not been populated, then
		// populate them with file nodes.
		populateEmptyDirectoryNodes(virtualPath, originLayerID, dirPath, chainLayersToFill)

		// In each outer loop, a layer is added to each relevant output chainLayer slice. Because the
		// outer loop is looping backwards (latest layer first), we ignore any files that are already in
		// each chainLayer, as they would have been overwritten.
		fillChainLayersWithFileNode(chainLayersToFill, newNode)

		// Add the fileNode to the node tree of the underlying layer.
		layer := currentChainLayer.latestLayer.(*Layer)
		layer.fileNodeTree.Insert(virtualPath, newNode)
	}

	return requiredTargets, nil
}

// populateEmptyDirectoryNodes populates the chain layers with file nodes for any directory paths
// that do not have an associated file node. This is done by creating a file node for each directory
// in the virtual path and then filling the chain layers with that file node.
func populateEmptyDirectoryNodes(virtualPath, originLayerID, extractDir string, chainLayersToFill []*chainLayer) {
	currentChainLayer := chainLayersToFill[0]

	runningDir := "/"
	dirs := strings.Split(path.Dir(virtualPath), "/")

	for _, dir := range dirs {
		runningDir = path.Join(runningDir, dir)

		// If the directory already exists in the current chain layer, then skip it.
		if currentChainLayer.fileNodeTree.Get(runningDir) != nil {
			continue
		}

		node := &fileNode{
			extractDir:    extractDir,
			originLayerID: originLayerID,
			virtualPath:   runningDir,
			isWhiteout:    false,
			mode:          fs.ModeDir,
		}
		fillChainLayersWithFileNode(chainLayersToFill, node)
	}
}

// handleSymlink returns the symlink header mode. Symlinks are handled by creating a fileNode with
// the symlink mode with additional metadata.
func (img *Image) handleSymlink(virtualPath, originLayerID string, tarReader *tar.Reader, header *tar.Header, isWhiteout bool, requiredTargets map[string]bool) (*fileNode, error) {
	targetPath := filepath.ToSlash(header.Linkname)
	if targetPath == "" {
		return nil, fmt.Errorf("symlink header has no target path")
	}

	if symlink.TargetOutsideRoot(virtualPath, targetPath) {
		log.Warnf("Found symlink that points outside the root, skipping: %q -> %q", virtualPath, targetPath)

		return nil, fmt.Errorf("%w: %q -> %q", ErrSymlinkPointsOutsideRoot, virtualPath, targetPath)
	}

	// Resolve the relative symlink path to an absolute path.
	if !path.IsAbs(targetPath) {
		targetPath = path.Clean(path.Join(path.Dir(virtualPath), targetPath))
	}

	requiredTargets[targetPath] = true

	return &fileNode{
		extractDir:    img.ExtractDir,
		originLayerID: originLayerID,
		virtualPath:   virtualPath,
		targetPath:    targetPath,
		isWhiteout:    isWhiteout,
		mode:          fs.FileMode(header.Mode) | fs.ModeSymlink,
	}, nil
}

// handleDir creates the directory specified by path, if it doesn't exist.
func (img *Image) handleDir(realFilePath, virtualPath, originLayerID string, tarReader *tar.Reader, header *tar.Header, isWhiteout bool) (*fileNode, error) {
	if _, err := os.Stat(realFilePath); err != nil {
		if err := os.MkdirAll(realFilePath, dirPermission); err != nil {
			return nil, fmt.Errorf("failed to create directory with realFilePath %s: %w", realFilePath, err)
		}
	}

	fileInfo := header.FileInfo()

	return &fileNode{
		extractDir:    img.ExtractDir,
		originLayerID: originLayerID,
		virtualPath:   virtualPath,
		isWhiteout:    isWhiteout,
		mode:          fileInfo.Mode() | fs.ModeDir,
		size:          fileInfo.Size(),
		modTime:       fileInfo.ModTime(),
	}, nil
}

// handleFile creates the file specified by path, and then copies the contents of the tarReader into
// the file.
func (img *Image) handleFile(realFilePath, virtualPath, originLayerID string, tarReader *tar.Reader, header *tar.Header, isWhiteout bool) (*fileNode, error) {
	parentDirectory := filepath.Dir(realFilePath)
	if err := os.MkdirAll(parentDirectory, dirPermission); err != nil {
		return nil, fmt.Errorf("failed to create parent directory %s: %w", parentDirectory, err)
	}
	// Write all files as read/writable by the current user, inaccessible by anyone else
	// Actual permission bits are stored in FileNode
	f, err := os.OpenFile(realFilePath, os.O_CREATE|os.O_RDWR, filePermission)

	if err != nil {
		return nil, err
	}
	defer f.Close()

	numBytes, err := io.Copy(f, io.LimitReader(tarReader, img.config.MaxFileBytes))
	if numBytes >= img.config.MaxFileBytes || errors.Is(err, io.EOF) {
		return nil, ErrFileReadLimitExceeded
	}

	if err != nil {
		return nil, fmt.Errorf("unable to copy file: %w", err)
	}

	fileInfo := header.FileInfo()

	return &fileNode{
		extractDir:    img.ExtractDir,
		originLayerID: originLayerID,
		virtualPath:   virtualPath,
		isWhiteout:    isWhiteout,
		mode:          fileInfo.Mode(),
		size:          fileInfo.Size(),
		modTime:       fileInfo.ModTime(),
	}, nil
}

// fillChainLayersWithFileNode fills the chain layers with a new fileNode.
func fillChainLayersWithFileNode(chainLayersToFill []*chainLayer, newNode *fileNode) {
	virtualPath := newNode.virtualPath
	for _, chainLayer := range chainLayersToFill {
		if node := chainLayer.fileNodeTree.Get(virtualPath); node != nil {
			// A newer version of the file already exists on a later chainLayer.
			// Since we do not want to overwrite a later layer with information
			// written in an earlier layer, skip this file.
			continue
		}

		// Check for a whited out parent directory.
		if inWhiteoutDir(chainLayer, virtualPath) {
			// The entire directory has been deleted, so no need to save this file.
			continue
		}

		// Add the file to the chain layer. If there is an error, then we fail open.
		// TODO: b/379154069 - Add logging for fail open errors.
		chainLayer.fileNodeTree.Insert(virtualPath, newNode)
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
