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

	v1 "github.com/google/go-containerregistry/pkg/v1"
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
	for pass := range u.MaxPass {
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
		_ = reader.Close()
		if err != nil {
			return err
		}
	}

	// Remove symlinks that have a nonexistent destination file or nonexistent destination directory.
	if err := symlink.RemoveObsoleteSymlinks(dir); err != nil {
		return fmt.Errorf("failed to remove obsolete symlinks from dir %q: %w", dir, err)
	}

	return nil
}

// safeWriteFile is a helper function that uses os.Root to write to a file with the specified
// permissions.
func safeWriteFile(root *os.Root, path string, content []byte, perm os.FileMode) error {
	// os.Root.OpenFile only supports the 9 least significant bits (0o777),
	// so ensure we strip any other bits (like setuid, sticky bit, etc.)
	normalizedPerm := perm & 0o777

	file, err := root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, normalizedPerm)
	if err != nil {
		log.Errorf("failed to open file %q: %v", path, err)
		return fmt.Errorf("failed to open file %q: %w", path, err)
	}

	_, err = file.Write(content)
	if err != nil {
		log.Errorf("failed to write file %q: %v", path, err)
		return fmt.Errorf("failed to write file %q: %w", path, err)
	}

	if err := file.Close(); err != nil {
		log.Errorf("failed to close file %q: %v", path, err)
		return fmt.Errorf("failed to close file %q: %w", path, err)
	}
	return nil
}

func unpack(dir string, reader io.Reader, symlinkResolution SymlinkResolution, symlinkErrStrategy SymlinkErrStrategy, requirer require.FileRequirer, requiredTargets map[string]bool, finalPass bool, maxSizeBytes int64) (map[string]bool, error) {
	tarReader := tar.NewReader(reader)

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to open root directory: %w", err)
	}
	defer root.Close()

	// Defensive copy of requiredTargets to avoid modifying the original.
	currRequiredTargets := make(map[string]bool)
	for t := range requiredTargets {
		currRequiredTargets[t] = true
	}

	for {
		header, err := tarReader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
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
		if _, err = root.Lstat(fullPath); err == nil {
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
			if err := os.MkdirAll(parent, fs.ModePerm); err != nil {
				log.Errorf("failed to create directory %q for file %q: %v", parent, fullPath, err)
				return nil, fmt.Errorf("failed to create directory %q for file %q: %w", parent, fullPath, err)
			}

			// Retain the original file permission but update it so we can always read and write the file.
			modeWithOwnerReadWrite := header.FileInfo().Mode() | 0600

			err = safeWriteFile(root, cleanPath, content, modeWithOwnerReadWrite)
			if err != nil {
				// TODO: b/412437775 - The error handling below is not ideal. It will become a mess if other
				// exceptions are added. Unfortunately, the os package does not export the underlying
				// error, so we have to do string matching for now.
				if strings.Contains(err.Error(), "path escapes from parent") {
					log.Warnf("path escapes from parent, potential path traversal attack detected: %q: %v", fullPath, err)
					continue
				}
				if strings.Contains(err.Error(), "too many levels of symbolic links") {
					log.Warnf("too many levels of symbolic links found: %q: %v", fullPath, err)
					continue
				}
				return nil, err
			}

			// TODO: b/406760694 - Remove this once the bug is fixed.

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
				// TODO: b/412444199 - Use the os.Root API to create symlinks when root.Symlink is available.
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

			content, err := func() ([]byte, error) {
				file, err := root.OpenFile(targetPath, os.O_RDONLY, 0644)
				if err != nil {
					return nil, fmt.Errorf("failed to open file %q: %w", targetPath, err)
				}
				content, err := io.ReadAll(file)
				if err != nil {
					return nil, fmt.Errorf("failed to read file %q: %w", targetPath, err)
				}
				if err := file.Close(); err != nil {
					return nil, fmt.Errorf("failed to close file %q: %w", targetPath, err)
				}
				return content, nil
			}()
			if err != nil {
				// If there is an error getting the contents of the target file, but this is not the final
				// pass, then we can skip. This is because another pass might resolve the target file.
				if !finalPass {
					continue
				}
				log.Errorf("failed to get contents of file %q: %v", targetPath, err)
				if symlinkErrStrategy == SymlinkErrLog {
					continue
				}
				if symlinkErrStrategy == SymlinkErrReturn {
					return nil, fmt.Errorf("failed to get contents of file %q: %w", targetPath, err)
				}
			}

			// Attempt to write the contents of the target in the symlink's path as a regular file.
			if err := safeWriteFile(root, cleanPath, content, 0644); err != nil {
				log.Errorf("failed to write symlink as regular file %q: %v", cleanPath, err)
				if symlinkErrStrategy == SymlinkErrReturn {
					return nil, fmt.Errorf("failed to write symlink as regular file %q: %w", cleanPath, err)
				}
			}

		case tar.TypeDir:
			continue
		}
	}

	return currRequiredTargets, nil
}
