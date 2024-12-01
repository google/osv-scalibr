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

// Package unpack contains functions to unpack an image.
package unpack

import (
	"bytes"
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
	"github.com/google/osv-scalibr/artifact/image/require"
	"github.com/google/osv-scalibr/artifact/image/symlink"
	scalibrtar "github.com/google/osv-scalibr/artifact/image/tar"
	"github.com/google/osv-scalibr/log"
)

const (
	// SymlinkRetain specifies that the symlink should be retained as a symlink.
	SymlinkRetain SymlinkResolution = "symlink_retain"
	// SymlinkIgnore specifies that the symlink should be ignored.
	SymlinkIgnore SymlinkResolution = "symlink_ignore"

	// SymlinkErrLog specifies that errors resolving symlinks are logged but not returned. Image unpacking continues.
	SymlinkErrLog SymlinkErrStrategy = "symlink_err_log"
	// SymlinkErrReturn specifies that errors resolving symlinks are returned, which stops unpacking the image.
	SymlinkErrReturn SymlinkErrStrategy = "symlink_err_return"

	// DefaultMaxPass is the default maximum number of times the image is unpacked to resolve symlinks.
	DefaultMaxPass = 3
	// DefaultMaxFileBytes is the default maximum size of files that will be unpacked. Larger files are ignored.
	// The max is large because some files, like kube-apiserver, are ~115MB.
	DefaultMaxFileBytes = 1024 * 1024 * 1024 // 1GB

	// name of sub directory where the squashed image files will be stored for layer-based extraction.
	squashedImageDirectory = "SQUASHED"
)

// SymlinkResolution specifies how to resolve symlinks.
type SymlinkResolution string

// SymlinkErrStrategy how to handle errors resolving symlinks.
type SymlinkErrStrategy string

// Unpacker unpacks the image.
type Unpacker struct {
	SymlinkResolution  SymlinkResolution
	SymlinkErrStrategy SymlinkErrStrategy
	MaxPass            int
	MaxSizeBytes       int64
	Requirer           require.FileRequirer
}

// UnpackerConfig configures how to unpack the image.
type UnpackerConfig struct {
	// SymlinkResolution specifies how to resolve symlinks.
	SymlinkResolution SymlinkResolution
	// SymlinkErrStrategy specifies how to handle symlink errors.
	SymlinkErrStrategy SymlinkErrStrategy
	// MaxPass limits the times the image is unpacked to resolve symlinks. 0 or less is essentially "unset" and will default to 2.
	MaxPass int
	// MaxFileBytes is the maximum size of files that will be unpacked. Larger files are ignored.
	MaxFileBytes int64
	// Requirer's FileRequired function is run on each file during unpacking. The file is unpacked if true and ignored if false.
	Requirer require.FileRequirer
}

// DefaultUnpackerConfig returns default configurations for a new Unpacker.
func DefaultUnpackerConfig() *UnpackerConfig {
	return &UnpackerConfig{
		SymlinkResolution:  SymlinkRetain,
		SymlinkErrStrategy: SymlinkErrLog,
		MaxPass:            DefaultMaxPass,
		MaxFileBytes:       DefaultMaxFileBytes,
		Requirer:           &require.FileRequirerAll{},
	}
}

// WithMaxPass returns a UnpackerConfig with the specified MaxPass param.
func (cfg *UnpackerConfig) WithMaxPass(maxPass int) *UnpackerConfig {
	cfg.MaxPass = maxPass
	return cfg
}

// WithMaxFileBytes returns a UnpackerConfig with the specified MaxFileBytes param.
func (cfg *UnpackerConfig) WithMaxFileBytes(maxFileBytes int64) *UnpackerConfig {
	cfg.MaxFileBytes = maxFileBytes
	return cfg
}

// WithSymlinkResolution returns a UnpackerConfig with the specified SymlinkResolution param.
func (cfg *UnpackerConfig) WithSymlinkResolution(resolution SymlinkResolution) *UnpackerConfig {
	cfg.SymlinkResolution = resolution
	return cfg
}

// WithRequirer returns a UnpackerConfig with the specified FileRequirer param.
func (cfg *UnpackerConfig) WithRequirer(requirer require.FileRequirer) *UnpackerConfig {
	cfg.Requirer = requirer
	return cfg
}

// NewUnpacker creates a new Unpacker.
func NewUnpacker(cfg *UnpackerConfig) (*Unpacker, error) {
	if cfg.SymlinkResolution == "" {
		return nil, errors.New("cfg.SymlinkResolution was not specified")
	}
	if cfg.SymlinkErrStrategy == "" {
		return nil, errors.New("cfg.SymlinkErrStrategy was not specified")
	}

	maxPass := DefaultMaxPass
	if cfg.MaxPass > 0 {
		maxPass = cfg.MaxPass
	}
	maxFileBytes := cfg.MaxFileBytes
	if cfg.MaxFileBytes <= 0 {
		maxFileBytes = 1024 * 1024 * 1024 * 1024 // 1TB
	}

	if cfg.Requirer == nil {
		return nil, errors.New("cfg.Requirer cannot be nil")
	}

	return &Unpacker{
		SymlinkResolution:  cfg.SymlinkResolution,
		SymlinkErrStrategy: cfg.SymlinkErrStrategy,
		MaxPass:            maxPass,
		MaxSizeBytes:       maxFileBytes,
		Requirer:           cfg.Requirer,
	}, nil
}

// UnpackSquashed squashes the layers of image then copies its contents to dir.
func (u *Unpacker) UnpackSquashed(dir string, image v1.Image) error {
	if u.SymlinkResolution == SymlinkIgnore {
		return fmt.Errorf("symlink resolution strategy %q is not supported", u.SymlinkResolution)
	}

	if dir == "" {
		return fmt.Errorf("dir cannot be root %q", dir)
	}
	if image == nil {
		return errors.New("image cannot be nil")
	}

	tarDir, err := os.MkdirTemp("", "image-tar-tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory for image tar: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tarDir); err != nil {
			log.Errorf("failed to remove temporary directory for image tar %q: %v", tarDir, err)
		}
	}()
	tarPath := filepath.Join(tarDir, "image.tar")
	defer func() {
		if err := os.Remove(tarPath); err != nil {
			log.Errorf("failed to remove temporary tar file %q: %v", tarPath, err)
		}
	}()
	if err := scalibrtar.SaveToTarball(tarPath, image); err != nil {
		if strings.Contains(err.Error(), "invalid tar header") {
			return fmt.Errorf("invalid tar header when saving image to tarball (error message %q) with %q", tarPath, err.Error())
		}
		return fmt.Errorf("failed to save image to tarball %q: %w", tarPath, err)
	}

	return u.UnpackSquashedFromTarball(dir, tarPath)
}

// UnpackSquashedFromTarball squashes the layers of an image from a tarball then
// copies its contents to dir.
func (u *Unpacker) UnpackSquashedFromTarball(dir string, tarPath string) error {
	// requiredTargets stores targets that symlinks point to.
	// This is needed because the symlink may be required by u.requirer, but the target may not be.
	requiredTargets := make(map[string]bool)
	for pass := 0; pass < u.MaxPass; pass++ {
		finalPass := false
		// Resolve symlinks on the last pass once all potential target files have been unpacked.
		if pass == u.MaxPass-1 {
			finalPass = true
		}
		reader, err := os.Open(tarPath)
		if err != nil {
			log.Errorf("Failed to open tarball of image at %q: %v", tarPath, err)
			return fmt.Errorf("failed to open tarball of image at %q: %w", tarPath, err)
		}
		log.Infof("Unpacking pass %d of %d", pass+1, u.MaxPass)
		requiredTargets, err = unpack(dir, reader, u.SymlinkResolution, u.SymlinkErrStrategy, u.Requirer, requiredTargets, finalPass, u.MaxSizeBytes)
		reader.Close()
		if err != nil {
			return err
		}
	}

	// Remove symlinks that have a non-existent destination file or non-existent destination directory.
	if err := symlink.RemoveObsoleteSymlinks(dir); err != nil {
		return fmt.Errorf("failed to remove obsolete symlinks from dir %q: %w", dir, err)
	}

	return nil
}

// UnpackLayers unpacks the contents of the layers of image into dir.
// Each layer is unpacked into a subdirectory of dir where the sub-directory name is the layer digest.
// The returned list contains the digests of the image layers from in order oldest/base layer first, and most-recent/top layer last.
func (u *Unpacker) UnpackLayers(dir string, image v1.Image) ([]string, error) {
	if u.SymlinkResolution == SymlinkIgnore {
		return nil, fmt.Errorf("symlink resolution strategy %q is not supported", u.SymlinkResolution)
	}

	if dir == "" {
		return nil, fmt.Errorf("dir cannot be root %q", dir)
	}
	if image == nil {
		return nil, errors.New("image cannot be nil")
	}

	// Adds the squashed image files into a sub directory in dir. The sub directory is named by
	// the constant, squashedImageDirectory.
	if err := u.addSquashedImageDirectory(dir, image); err != nil {
		return nil, fmt.Errorf("failed to add squashed image directory: %w", err)
	}

	layers, err := image.Layers()

	if err != nil {
		return nil, fmt.Errorf("failed to get layers from image: %w", err)
	}

	layerDigests := []string{}
	for _, layer := range layers {
		digest, err := layer.Digest()
		if err != nil {
			return nil, fmt.Errorf("failed to get digest of layer: %w", err)
		}
		layerDigests = append(layerDigests, digest.String())

		layerPath := filepath.Join(dir, strings.Replace(digest.String(), ":", "-", -1))
		os.Mkdir(layerPath, fs.ModePerm)

		// requiredTargets stores targets that symlinks point to.
		// This is needed because the symlink may be required by u.requirer, but the target may not be.
		requiredTargets := make(map[string]bool)
		for pass := 0; pass < u.MaxPass; pass++ {
			finalPass := false
			// Resolve symlinks on the last pass once all potential target files have been unpacked.
			if pass == u.MaxPass-1 {
				finalPass = true
			}

			reader, err := layer.Uncompressed()
			if err != nil {
				return nil, fmt.Errorf("failed to uncompress layer: %w", err)
			}

			if requiredTargets, err = unpack(layerPath, reader, u.SymlinkResolution, u.SymlinkErrStrategy, u.Requirer, requiredTargets, finalPass, u.MaxSizeBytes); err != nil {
				return nil, fmt.Errorf("failed to unpack layer %q: %w", digest.String(), err)
			}
		}

		// If inter-layer symlinks can be resolved by looking into the SQUASHED file system, then they
		// will, otherwise they will be deleted.
		if err := symlink.ResolveInterLayerSymlinks(dir, digest.String(), squashedImageDirectory); err != nil {
			return nil, fmt.Errorf("failed to resolve symlinks in layer: %w", err)
		}
	}

	return layerDigests, nil
}

func unpack(dir string, reader io.Reader, symlinkResolution SymlinkResolution, symlinkErrStrategy SymlinkErrStrategy, requirer require.FileRequirer, requiredTargets map[string]bool, finalPass bool, maxSizeBytes int64) (map[string]bool, error) {
	tarReader := tar.NewReader(reader)

	// Defensive copy of requiredTargets to avoid modifying the original.
	currRequiredTargets := make(map[string]bool)
	for t := range requiredTargets {
		currRequiredTargets[t] = true
	}

	// Tar extraction inspired by `singlePass` in cloud/containers/workflow/extraction/layerextract.go
	for {
		header, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read next header in tarball: %w", err)
		}

		if header.Size > maxSizeBytes {
			log.Infof("skipping file %q because its size (%d bytes) is larger than the max size (%d bytes)", header.Name, header.Size, maxSizeBytes)
			continue
		}

		cleanPath := path.Clean(header.Name)
		fullPath := path.Join(dir, cleanPath)

		// Skip files already unpacked.
		// Lstat is used instead of Stat to avoid following symlinks, because their targets may not exist yet.
		if _, err = os.Lstat(fullPath); err == nil {
			continue
		}

		// Skip files that are not required by extractors and are not targets of required symlinks.
		// Try multiple paths variations
		// (with parent dir, without leading slash, with leading slash). For example:
		// - `fullPath`: `tmp/12345/etc/os-release`. This is used when actually writing the file to disk.
		// - `cleanPath`: `etc/os-release`. This is used when checking if the file is required.
		// - `filepath.Join("/", cleanPath)`: `/etc/os-release`. This is used when checking if the file is required.
		required := false
		for _, p := range []string{fullPath, cleanPath, filepath.Join("/", cleanPath)} {
			if requirer.FileRequired(p, header.FileInfo()) {
				required = true
				break
			}
			if _, ok := currRequiredTargets[p]; ok {
				required = true
				break
			}
		}
		if !required {
			continue
		}

		switch header.Typeflag {
		case tar.TypeReg:
			buf := new(bytes.Buffer)
			_, err = io.Copy(buf, tarReader)
			if err != nil {
				return nil, err
			}
			content := buf.Bytes()

			parent := filepath.Dir(fullPath)
			err := os.MkdirAll(parent, fs.ModePerm)
			if err != nil {
				log.Errorf("failed to create directory %q: %v", parent, err)
				return nil, fmt.Errorf("failed to create directory %q: %w", parent, err)
			}

			// Retain the original file permission but update it so we can always read and write the file.
			modeWithOwnerReadWrite := header.FileInfo().Mode() | 0600
			err = os.WriteFile(fullPath, content, modeWithOwnerReadWrite)
			if err != nil {
				log.Errorf("failed to write file %q: %v", fullPath, err)
				return nil, fmt.Errorf("failed to write file %q: %w", fullPath, err)
			}

		case tar.TypeLink, tar.TypeSymlink:
			parent := filepath.Dir(fullPath)
			if err := os.MkdirAll(parent, fs.ModePerm); err != nil {
				log.Errorf("failed to create directory %q: %v", parent, err)
				if symlinkErrStrategy == SymlinkErrReturn {
					return nil, fmt.Errorf("failed to create directory %q: %w", parent, err)
				}
			}

			target := header.Linkname
			targetPath := target

			if symlink.TargetOutsideRoot(cleanPath, target) {
				log.Warnf("Found symlink that points outside the root, skipping: %q -> %q", cleanPath, target)
				continue
			}

			// Only absolute destination need to be prepended. Relative destinations still work.
			if filepath.IsAbs(targetPath) {
				targetPath = filepath.Join(dir, target)
				currRequiredTargets[target] = true
			} else {
				// Track the absolute path of the target so it is not skipped in the next pass.
				targetAbs := filepath.Join(filepath.Dir(cleanPath), target)
				currRequiredTargets[targetAbs] = true
			}

			if symlinkResolution == SymlinkRetain {
				if err := os.Symlink(targetPath, fullPath); err != nil {
					log.Errorf("failed to symlink %q to %q: %v", fullPath, targetPath, err)
					if symlinkErrStrategy == SymlinkErrReturn {
						return nil, fmt.Errorf("failed to symlink %q to %q: %w", fullPath, targetPath, err)
					}
					continue
				}
				log.Infof("created symlink %q to %q", fullPath, targetPath)
				continue
			}

			content, err := os.ReadFile(targetPath)
			if err != nil {
				if !finalPass {
					continue
				}
				log.Errorf("failed to read file %q: %v", targetPath, err)
				if symlinkErrStrategy == SymlinkErrLog {
					continue
				}
				if symlinkErrStrategy == SymlinkErrReturn {
					return nil, fmt.Errorf("failed to read file %q: %w", targetPath, err)
				}
			}

			if err := os.WriteFile(fullPath, content, 0644); err != nil {
				log.Errorf("failed to write file %q: %v", fullPath, err)
				if symlinkErrStrategy == SymlinkErrReturn {
					return nil, fmt.Errorf("failed to write file %q: %w", fullPath, err)
				}
			}

		case tar.TypeDir:
			continue
		}
	}

	return currRequiredTargets, nil
}

// addSquashedImageDirectory adds a sub directory with name denoted by squashedImageDirectory that
// holds all files present in the squashed image. The squashed sub directory is used to resolve
// inter-layer symlinks.
func (u *Unpacker) addSquashedImageDirectory(root string, image v1.Image) error {
	squashedImagePath := filepath.Join(root, squashedImageDirectory)

	os.Mkdir(squashedImagePath, fs.ModePerm)

	if err := u.UnpackSquashed(squashedImagePath, image); err != nil {
		return fmt.Errorf("failed to unpack all squashed image: %w", err)
	}
	return nil
}
