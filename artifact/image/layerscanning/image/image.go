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

// Package image provides functionality to scan a linux container image by layers for software
// inventory. Note that this package does not support Windows images as they are not as widely used
// as linux images.
package image

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"archive/tar"

	"github.com/docker/docker/client"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	scalibrimage "github.com/google/osv-scalibr/artifact/image"
	"github.com/google/osv-scalibr/artifact/image/symlink"
	"github.com/google/osv-scalibr/artifact/image/whiteout"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/log"
	"github.com/opencontainers/go-digest"
)

const (
	// DefaultMaxFileBytes is the default maximum size of files that will be unpacked. Larger files are ignored.
	// The max is large because some files are hundreds of megabytes.
	DefaultMaxFileBytes = 1024 * 1024 * 1024 // 1GB
	// DefaultMaxSymlinkDepth is the default maximum symlink depth. This should be no more than 8,
	// since that is the maximum number of symlinks the os.Root API will handle. From the os.Root API,
	// "8 is __POSIX_SYMLOOP_MAX (the minimum allowed value for SYMLOOP_MAX), and a common limit".
	DefaultMaxSymlinkDepth = 6
	// filePermission represents the permission bits for a file, which are minimal since files in the
	// layer scanning use case are read-only.
	filePermission = 0600
	// dirPermission represents the permission bits for a directory, which are minimal since
	// directories in the layer scanning use case are read-only.
	dirPermission = 0700

	dockerImageNameSeparator = ":"
	tarFileNameSeparator     = "_"
	tarFileExtension         = ".tar"
)

var (
	// ErrFileReadLimitExceeded is returned when a file exceeds the read limit. This is intended to
	// prevent zip bomb attacks, for example.
	ErrFileReadLimitExceeded = errors.New("file exceeds read limit")
	// ErrSymlinkPointsOutsideRoot is returned when a symlink points outside the root.
	ErrSymlinkPointsOutsideRoot = errors.New("symlink points outside the root")
	// ErrInvalidConfig is returned when the image config is invalid.
	ErrInvalidConfig = errors.New("invalid image config")
	// ErrNoLayersFound is returned when no layers are found in the image.
	ErrNoLayersFound = errors.New("no layers found in image")
)

// ========================================================
// IMAGE TYPES AND METHODS
// ========================================================

// Config contains the configuration to load an Image.
type Config struct {
	MaxFileBytes    int64
	MaxSymlinkDepth int
}

// DefaultConfig returns the default configuration to load an Image.
func DefaultConfig() *Config {
	return &Config{
		MaxFileBytes:    DefaultMaxFileBytes,
		MaxSymlinkDepth: DefaultMaxSymlinkDepth,
	}
}

// validateConfig makes sure that the config values will not cause issues while extracting the
// image. Checks include:
//
//	(1) MaxFileBytes is positive.
//	(2) MaxSymlinkDepth is non-negative.
func validateConfig(config *Config) error {
	if config.MaxFileBytes <= 0 {
		return fmt.Errorf("%w: max file bytes must be positive: %d", ErrInvalidConfig, config.MaxFileBytes)
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
	size           int64
	BaseImageIndex int
	contentBlob    *os.File
}

// FS returns the filesystem of the top-most chainlayer of the image. All available files should
// be present in the filesystem returned.
func (img *Image) FS() scalibrfs.FS {
	if len(img.chainLayers) == 0 {
		emptyChainLayer := &chainLayer{
			fileNodeTree: NewNode(img.config.MaxSymlinkDepth),
		}
		return emptyChainLayer.FS()
	}
	return img.chainLayers[len(img.chainLayers)-1].FS()
}

// Layers returns the individual layers of the image.
func (img *Image) Layers() ([]scalibrimage.Layer, error) {
	chainLayers, err := img.ChainLayers()
	if err != nil {
		return nil, err
	}
	scalibrLayers := make([]scalibrimage.Layer, 0, len(chainLayers))
	for _, chainLayer := range chainLayers {
		scalibrLayers = append(scalibrLayers, chainLayer.Layer())
	}
	return scalibrLayers, nil
}

// ChainLayers returns the chain layers of the image.
func (img *Image) ChainLayers() ([]scalibrimage.ChainLayer, error) {
	if len(img.chainLayers) == 0 {
		return nil, ErrNoLayersFound
	}
	scalibrChainLayers := make([]scalibrimage.ChainLayer, 0, len(img.chainLayers))
	for _, chainLayer := range img.chainLayers {
		scalibrChainLayers = append(scalibrChainLayers, chainLayer)
	}
	return scalibrChainLayers, nil
}

// CleanUp removes the temporary directory used to store the image files.
func (img *Image) CleanUp() error {
	if img.contentBlob == nil {
		return nil
	}

	if err := img.contentBlob.Close(); err != nil {
		log.Warnf("failed to close content blob: %v", err)
	}

	err := os.Remove(img.contentBlob.Name())
	// Make sure the image is alive so that the runtime cleanup doesn't run
	// until this cleanup is finished.
	runtime.KeepAlive(img)

	return err
}

// Size returns the size of the underlying directory of the image in bytes.
func (img *Image) Size() int64 {
	return img.size
}

// FromRemoteName creates an Image from a remote container image name.
func FromRemoteName(imageName string, config *Config, imageOptions ...remote.Option) (*Image, error) {
	v1Image, err := scalibrimage.V1ImageFromRemoteName(imageName, imageOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to load image from remote name %q: %w", imageName, err)
	}
	return FromV1Image(v1Image, config)
}

// CreateTarBallFromImage creates a tarball from a local docker image. This is the API version of 'docker save image' command
func createTarBallFromImage(imageName string) (string, error) {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return "", fmt.Errorf("unable to create docker client to untar image  %s: %w", imageName, err)
	}

	inputStream, err := dockerClient.ImageSave(context.Background(), []string{imageName})
	if err != nil {
		return "", fmt.Errorf("unable to create docker stream to untar image %s: %w", imageName, err)
	}
	defer inputStream.Close()

	tarFileName := strings.ReplaceAll(imageName, dockerImageNameSeparator, tarFileNameSeparator) + tarFileExtension
	log.Infof("Tarfile name is %s", tarFileName)

	fileFd, err := os.CreateTemp("", tarFileName)
	if err != nil {
		return "", fmt.Errorf("unable to create file to untar image %s: %w", imageName, err)
	}

	_, err = io.Copy(fileFd, inputStream)
	if err != nil {
		fileFd.Close()
		errVal := os.Remove(fileFd.Name())
		if !os.IsNotExist(errVal) {
			log.Warnf("unable to remove file %s: %v", fileFd.Name(), errVal)
		}
		return "", fmt.Errorf("unable to write to tarfile for image %s: %w", imageName, err)
	}

	fileFd.Close()
	return fileFd.Name(), nil
}

// Check if the imageName is of the form imageName:imageTag
func validateImageNameAndTag(imageName string) error {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer func() {
		if err := dockerClient.Close(); err != nil {
			log.Warnf("failed to close docker client: %v", err)
		}
	}()
	_, err = dockerClient.ImageInspect(context.Background(), imageName)
	return err
}

// FromLocalDockerImage reads an image from the local docker daemon
// We convert the image to a tarball, and then pass it to the FromTarball function which does all that is necessary
func FromLocalDockerImage(imageName string, config *Config) (*Image, error) {
	var tarBallName string
	var img *Image
	var errVal error
	// First, the image name *MUST* always be of the form imageName:imageTag
	if !strings.Contains(imageName, dockerImageNameSeparator) {
		return nil, errors.New("image name MUST be specified with a tag and be of the form <image_name>:<tag>")
	}
	// Now, check if the image actually exists on the local hard disk
	err := validateImageNameAndTag(imageName)
	if err != nil {
		return nil, fmt.Errorf("image %s error while trying to access it: %w", imageName, err)
	}
	// Now, create a tarball out of the image by using the API equivalent of 'docker save image:tag'
	tarBallName, err = createTarBallFromImage(imageName)
	if err != nil {
		return nil, fmt.Errorf("unable to use image %s: %w", imageName, err)
	}
	img, errVal = FromTarball(tarBallName, config)

	err = os.Remove(tarBallName)
	if err != nil {
		log.Warnf("unable to remove the tarball %s: %v", tarBallName, err)
	}
	if errVal != nil {
		return nil, fmt.Errorf("unable to use image %s: %w", imageName, err)
	}
	return img, errVal
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
//
// Note: The image returned should be cleaned up by calling CleanUp() by the caller once it is no
// longer needed.
func FromV1Image(v1Image v1.Image, config *Config) (*Image, error) {
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid image config: %w", err)
	}

	var history []v1.History

	configFile, err := v1Image.ConfigFile()
	// If the config file is not found, then layers will not have history information.
	if err != nil {
		log.Warnf("failed to load config file: %v", err)
	} else {
		history = configFile.History
	}

	v1Layers, err := v1Image.Layers()
	if err != nil {
		return nil, fmt.Errorf("failed to load layers: %w", err)
	}

	chainLayers, err := initializeChainLayers(v1Layers, history, config.MaxSymlinkDepth)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize chain layers: %w", err)
	}

	imageContentBlob, err := os.CreateTemp("", "image-blob-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create image content file: %w", err)
	}

	baseImageIndex, err := findBaseImageIndex(history)
	if err != nil {
		baseImageIndex = -1
	}

	outputImage := &Image{
		chainLayers:    chainLayers,
		config:         config,
		BaseImageIndex: baseImageIndex,
		contentBlob:    imageContentBlob,
	}

	// Attach a cleanup function to the outputImage.
	// This is done to ensure that the imageContentBlob file is removed even if the caller does not
	// call CleanUp() or there is an error during creation of the image.
	runtime.AddCleanup(outputImage, func(file *os.File) {
		// Defensively close the file. Ignore the error because the file may already be closed.
		_ = file.Close()
		err := os.Remove(file.Name())
		if err == nil {
			log.Warnf("%q was removed through cleanup function. This is unexpected as the user should have called CleanUp()", file.Name())
			return
		}
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		log.Warnf("%q failed to be removed through GC cleanup function: %v", file.Name(), err)
	}, imageContentBlob)

	// Since the layers are in reverse order, the v1LayerIndex starts at the last layer and works
	// its way to the first layer.
	v1LayerIndex := len(v1Layers) - 1

	// Reverse loop through the layers to start from the latest layer first. This allows us to skip
	// all files already seen.
	for i := len(chainLayers) - 1; i >= 0; i-- {
		chainLayer := chainLayers[i]

		// If the layer is empty, then there is nothing to do.
		if chainLayer.latestLayer.IsEmpty() {
			continue
		}

		if v1LayerIndex < 0 {
			return nil, handleImageError(outputImage, fmt.Errorf("mismatch between v1 layers and chain layers, on v1 layer index %d, but only %d v1 layers", v1LayerIndex, len(v1Layers)))
		}

		chainLayersToFill := chainLayers[i:]

		v1Layer := v1Layers[v1LayerIndex]
		layerReader, err := v1Layer.Uncompressed()
		if err != nil {
			return nil, handleImageError(outputImage, err)
		}
		v1LayerIndex--

		err = func() error {
			// Manually close at the end of the for loop.
			defer layerReader.Close()

			tarReader := tar.NewReader(layerReader)
			if err := fillChainLayersWithFilesFromTar(outputImage, tarReader, chainLayersToFill); err != nil {
				return fmt.Errorf("failed to fill chain layer with v1 layer tar: %w", err)
			}

			return nil
		}()

		if err != nil {
			return nil, handleImageError(outputImage, err)
		}
	}

	return outputImage, nil
}

// ========================================================
// Helper functions
// ========================================================

// handleImageError cleans up the image and returns the provided error. The image is cleaned up
// regardless of the error, as the image is in an invalid state if an error is returned.
func handleImageError(image *Image, err error) error {
	if image != nil {
		if err := image.CleanUp(); err != nil {
			log.Warnf("failed to clean up image: %v", err)
		}
	}
	return err
}

// validateHistory makes sure that the number of v1 layers matches the number of non-empty history
// entries. Some images may have corrupted or invalid history entries. If so, then some layer
// metadata such as the build commands cannot be matched with the v1 layers.
func validateHistory(v1Layers []v1.Layer, history []v1.History) error {
	nonEmptyHistoryEntries := 0
	for _, entry := range history {
		if !entry.EmptyLayer {
			nonEmptyHistoryEntries++
		}
	}

	if len(v1Layers) != nonEmptyHistoryEntries {
		return fmt.Errorf("mismatch between v1 layers and history entries, %d v1 layers, but %d non-empty history entries", len(v1Layers), nonEmptyHistoryEntries)
	}
	return nil
}

// initializeChainLayers initializes the chain layers based on the config file history, the
// v1.Layers found in the image from the tarball, and the max symlink depth.
func initializeChainLayers(v1Layers []v1.Layer, history []v1.History, maxSymlinkDepth int) ([]*chainLayer, error) {
	var chainLayers []*chainLayer

	chainIDs, err := chainIDsForV1Layers(v1Layers)
	if err != nil {
		log.Warnf("Failed to get chainIDs for v1 layers: %v", err)
	}
	// Defensively extend the length of the chainIDs slice to the length of the v1Layers slice.
	if len(chainIDs) < len(v1Layers) {
		log.Warnf("initializeChainLayers: ChainIDs slice is shorter than v1Layers slice, this should not happen")
		for i := len(chainIDs); i < len(v1Layers); i++ {
			chainIDs = append(chainIDs, digest.Digest(""))
		}
	}

	// If history is invalid, then just create the chain layers based on the v1 layers.
	if err := validateHistory(v1Layers, history); err != nil {
		log.Warnf("Invalid history entries found in image, layer metadata may not be populated: %v", err)

		for i, v1Layer := range v1Layers {
			chainLayers = append(chainLayers, &chainLayer{
				fileNodeTree: NewNode(maxSymlinkDepth),
				index:        i,
				chainID:      chainIDs[i],
				latestLayer:  convertV1Layer(v1Layer, "", false, maxSymlinkDepth),
			})
		}
		return chainLayers, nil
	}

	// v1LayerIndex tracks the next v1.Layer that should populated in a chain layer. This does not
	// include empty layers.
	v1LayerIndex := 0
	// historyIndex tracks the chain layer index including empty layers.
	historyIndex := 0

	// First loop through the history entries found in the config file. If the entry is an empty
	// layer, then create an empty chain layer. Otherwise, convert the v1.Layer to a scalibr Layer
	// and create a chain layer with it.
	for _, entry := range history {
		if entry.EmptyLayer {
			chainLayers = append(chainLayers, &chainLayer{
				fileNodeTree: NewNode(maxSymlinkDepth),
				index:        historyIndex,
				latestLayer: &Layer{
					buildCommand: entry.CreatedBy,
					isEmpty:      true,
					fileNodeTree: NewNode(maxSymlinkDepth),
				},
			})
			historyIndex++
			continue
		}

		if v1LayerIndex >= len(v1Layers) {
			return nil, fmt.Errorf("config history contains more non-empty layers than expected (%d)", len(v1Layers))
		}

		nextNonEmptyLayer := v1Layers[v1LayerIndex]
		chainLayer := &chainLayer{
			fileNodeTree: NewNode(maxSymlinkDepth),
			index:        historyIndex,
			chainID:      chainIDs[v1LayerIndex],
			latestLayer:  convertV1Layer(nextNonEmptyLayer, entry.CreatedBy, false, maxSymlinkDepth),
		}
		chainLayers = append(chainLayers, chainLayer)

		historyIndex++
		v1LayerIndex++
	}

	// If there are any remaining v1.Layers, then the history in the config file is missing entries.
	// This can happen depending on the build process used to create an image.
	for v1LayerIndex < len(v1Layers) {
		chainLayers = append(chainLayers, &chainLayer{
			fileNodeTree: NewNode(maxSymlinkDepth),
			index:        historyIndex,
			chainID:      chainIDs[v1LayerIndex],
			latestLayer:  convertV1Layer(v1Layers[v1LayerIndex], "", false, maxSymlinkDepth),
		})
		v1LayerIndex++
		historyIndex++
	}

	return chainLayers, nil
}

// fillChainLayersWithFilåesFromTar fills the chain layers with the files found in the tar. The
// chainLayersToFill are the chain layers that will be filled with the files via the virtual
// filesystem.
func fillChainLayersWithFilesFromTar(img *Image, tarReader *tar.Reader, chainLayersToFill []*chainLayer) error {
	if len(chainLayersToFill) == 0 {
		return errors.New("no chain layers provided, this should not happen")
	}

	currentChainLayer := chainLayersToFill[0]

	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("could not read tar: %w", err)
		}

		// Preemptively skip files that are too large.
		if header.Size > img.config.MaxFileBytes {
			log.Infof("skipping file %q because its size (%d bytes) is larger than the max size (%d bytes)", header.Name, header.Size, img.config.MaxFileBytes)
			continue
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

		var newVirtualFile *virtualFile
		switch header.Typeflag {
		case tar.TypeDir:
			newVirtualFile = img.handleDir(virtualPath, header, isWhiteout)
		case tar.TypeReg:
			newVirtualFile, err = img.handleFile(virtualPath, tarReader, header, isWhiteout)
		case tar.TypeSymlink, tar.TypeLink:
			newVirtualFile, err = img.handleSymlink(virtualPath, header, isWhiteout)
		default:
			log.Warnf("unsupported file type: %v, path: %s", header.Typeflag, header.Name)
			continue
		}

		if err != nil {
			// If the error is due to a file read limit being exceeded or a symlink pointing outside the
			// root, then we fail open and skip the file.
			if errors.Is(err, ErrFileReadLimitExceeded) || errors.Is(err, ErrSymlinkPointsOutsideRoot) {
				log.Warnf("failed to handle tar entry with path %s: %v", virtualPath, err)
				continue
			}
			return fmt.Errorf("failed to handle tar entry with path %s: %w", virtualPath, err)
		}

		layer := currentChainLayer.latestLayer.(*Layer)

		// If the virtual path has any directories and those directories have not been populated, then
		// populate them with file nodes.
		populateEmptyDirectoryNodes(virtualPath, layer, chainLayersToFill)

		// Add the fileNode to the node tree of the underlying layer.
		if err := layer.fileNodeTree.Insert(virtualPath, newVirtualFile); err != nil {
			log.Warnf("failed to insert virtual file %q into layer: %v", virtualPath, err)
		}

		// In each outer loop, a layer is added to each relevant output chainLayer slice. Because the
		// outer loop is looping backwards (latest layer first), we ignore any files that are already in
		// each chainLayer, as they would have been overwritten.
		fillChainLayersWithVirtualFile(chainLayersToFill, newVirtualFile)
	}
	return nil
}

// populateEmptyDirectoryNodes populates the chain layers with file nodes for any directory paths
// that do not have an associated file node. This is done by creating a file node for each directory
// in the virtual path and then filling the chain layers with that file node.
func populateEmptyDirectoryNodes(virtualPath string, layer *Layer, chainLayersToFill []*chainLayer) {
	currentChainLayer := chainLayersToFill[0]

	runningDir := "/"
	dirs := strings.Split(path.Dir(virtualPath), "/")

	for _, dir := range dirs {
		runningDir = path.Join(runningDir, dir)

		// If the directory already exists in the current chain layer, then skip it.
		if vf, _ := currentChainLayer.fileNodeTree.Get(runningDir, false); vf != nil {
			continue
		}

		node := &virtualFile{
			virtualPath: runningDir,
			isWhiteout:  false,
			mode:        fs.ModeDir,
		}

		// Add the fileNode to the node tree of the underlying layer.
		if err := layer.fileNodeTree.Insert(runningDir, node); err != nil {
			log.Warnf("failed to insert virtual file %q into layer: %v", runningDir, err)
		}

		// Add the fileNode to the node tree of the underlying chain layers.q
		fillChainLayersWithVirtualFile(chainLayersToFill, node)
	}
}

// handleSymlink returns the symlink header mode. Symlinks are handled by creating a virtual file
// with the symlink mode with additional metadata.
func (img *Image) handleSymlink(virtualPath string, header *tar.Header, isWhiteout bool) (*virtualFile, error) {
	targetPath := filepath.ToSlash(header.Linkname)
	if targetPath == "" {
		return nil, errors.New("symlink header has no target path")
	}

	if symlink.TargetOutsideRoot(virtualPath, targetPath) {
		log.Warnf("Found symlink that points outside the root, skipping: %q -> %q", virtualPath, targetPath)
		return nil, fmt.Errorf("%w: %q -> %q", ErrSymlinkPointsOutsideRoot, virtualPath, targetPath)
	}

	// Resolve the relative symlink path to an absolute path.
	if !path.IsAbs(targetPath) {
		targetPath = path.Clean(path.Join(path.Dir(virtualPath), targetPath))
	}

	return &virtualFile{
		virtualPath: virtualPath,
		targetPath:  targetPath,
		isWhiteout:  isWhiteout,
		mode:        fs.FileMode(header.Mode) | fs.ModeSymlink,
	}, nil
}

// handleDir creates the directory specified by path, if it doesn't exist.
func (img *Image) handleDir(virtualPath string, header *tar.Header, isWhiteout bool) *virtualFile {
	fileInfo := header.FileInfo()

	return &virtualFile{
		virtualPath: virtualPath,
		isWhiteout:  isWhiteout,
		mode:        fileInfo.Mode() | fs.ModeDir,
		size:        fileInfo.Size(),
		modTime:     fileInfo.ModTime(),
	}
}

// handleFile creates the file specified by path, and then copies the contents of the tarReader into
// the file. The function returns a virtual file, which is meant to represent the file in a virtual
// filesystem.
func (img *Image) handleFile(virtualPath string, tarReader *tar.Reader, header *tar.Header, isWhiteout bool) (*virtualFile, error) {
	// Use LimitReader in case the header.Size is incorrect.
	numBytes, err := img.contentBlob.ReadFrom(io.LimitReader(tarReader, img.config.MaxFileBytes))
	if numBytes >= img.config.MaxFileBytes || errors.Is(err, io.EOF) {
		return nil, ErrFileReadLimitExceeded
	}

	if err != nil {
		return nil, fmt.Errorf("unable to copy file: %w", err)
	}

	// Record the offset of the file in the content blob before adding the new bytes. The offset is
	// the current size of the content blob.
	offset := img.size
	// Update the image size with the number of bytes read into the content blob.
	img.size += numBytes
	fileInfo := header.FileInfo()

	return &virtualFile{
		virtualPath: virtualPath,
		isWhiteout:  isWhiteout,
		mode:        fileInfo.Mode(),
		modTime:     fileInfo.ModTime(),
		size:        numBytes,
		reader:      io.NewSectionReader(img.contentBlob, offset, numBytes),
	}, nil
}

// fillChainLayersWithVirtualFile fills the chain layers with a new fileNode.
func fillChainLayersWithVirtualFile(chainLayersToFill []*chainLayer, newNode *virtualFile) {
	virtualPath := newNode.virtualPath
	for _, chainLayer := range chainLayersToFill {
		// We want the raw final symlink when checking for existence.
		if node, _ := chainLayer.fileNodeTree.Get(virtualPath, false); node != nil {
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
		if err := chainLayer.fileNodeTree.Insert(virtualPath, newNode); err != nil {
			log.Warnf("failed to insert virtual file %q into chain layer: %v", virtualPath, err)
		}
	}
}

// inWhiteoutDir returns whether the file is in a whiteout directory.
// TODO: b/379094217 - Verify that this works for opaque whiteouts.
func inWhiteoutDir(layer *chainLayer, filePath string) bool {
	for filePath != "" {
		dirname := path.Dir(filePath)
		if filePath == dirname {
			break
		}

		node, err := layer.fileNodeTree.Get(dirname, false)
		if err != nil {
			return false
		}
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
