// Copyright 2026 Google LLC
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

// Package tempdir provides a single root temporary directory for the lifetime
// of the process with automatic signal-based cleanup and optional debug mode.
package tempdir

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
)

var (
	root     *os.Root
	errRoot  error
	once     sync.Once
	debug    bool
	rootPath string
)

// SetDebug disables automatic cleanup when enabled.
func SetDebug(enabled bool) {
	debug = enabled
}

// initRoot creates the root directory once.
func initRoot() {
	rootPath, errRoot = os.MkdirTemp("", "osv-scalibr-run-*")
	if errRoot != nil {
		return
	}
	root, errRoot = os.OpenRoot(rootPath)
	if errRoot != nil {
		return
	}
	setupSignalCleanup()
}

// Root returns the root directory for the current run.
func Root() (*os.Root, error) {
	once.Do(initRoot)
	if errRoot != nil {
		return nil, errRoot
	}
	return root, nil
}

// GetRootPath returns the root directory path for the current run.
func GetRootPath() (string, error) {
	_, err := Root()
	if err != nil {
		return "", err
	}
	return rootPath, nil
}

// CreateDir creates and opens a subdirectory as a new os.Root (chroot-like).
func CreateDir(name string) (string, *os.Root, error) {
	r, err := Root()
	if err != nil {
		return "", nil, err
	}
	// Ensure dir exists
	if err := r.MkdirAll(name, 0o755); err != nil && !os.IsExist(err) {
		return "", nil, err
	}

	newRoot, err := r.OpenRoot(name)
	if err != nil {
		return "", nil, err
	}
	return name, newRoot, nil
}

// CreateExtractorDir returns a sub-root for the extractor.
// Layout: <SCALIBR-TMP-ROOT>/extractor/<plugin>/<filename>
func CreateExtractorDir(plugin, filename string) (string, *os.Root, error) {
	dir := filepath.Join("extractor", plugin, filepath.Base(filename))
	return CreateDir(dir)
}

// CreateEnricherDir returns a sub-root for the enricher.
// Layout: <SCALIBR-TMP-ROOT>/enricher/<plugin>/<filename>
func CreateEnricherDir(plugin, filename string) (string, *os.Root, error) {
	dir := filepath.Join("enricher", plugin, filepath.Base(filename))
	return CreateDir(dir)
}

// CreateDetectorDir returns a sub-root for the detector.
// Layout: <SCALIBR-TMP-ROOT>/enricher/<plugin>/<filename>
func CreateDetectorDir(plugin, filename string) (string, *os.Root, error) {
	dir := filepath.Join("detector", plugin, filepath.Base(filename))
	return CreateDir(dir)
}

// CreateFile creates a temp file under the given (sub)directory using os.Root.
// Since os.Root does not have CreateTemp yet, we implement it manually.
func CreateFile(dir, pattern string) (string, *os.File, error) {
	r, err := Root()
	if err != nil {
		return "", nil, err
	}

	targetDir := "."
	if dir != "" {
		targetDir = dir
		if err := r.MkdirAll(targetDir, 0o755); err != nil {
			return "", nil, fmt.Errorf("failed to create dir %s: %w", targetDir, err)
		}
	}

	// os.Root.CreateTemp is not available
	f, err := os.CreateTemp("", pattern) // temporary in default temp
	if err != nil {
		return "", nil, err
	}
	fname := f.Name()
	f.Close()

	// Move it under our root (safer than CreateTemp with full path)
	newName := filepath.Join(rootPath, targetDir, filepath.Base(fname))
	if err := os.Rename(fname, newName); err != nil {
		os.Remove(fname)
		return "", nil, err
	}

	finalF, err := r.OpenFile(filepath.Join(targetDir, filepath.Base(newName)), os.O_RDWR, 0o666)
	if err != nil {
		os.Remove(newName)
		return "", nil, err
	}

	return newName, finalF, nil
}

// RemoveAll removes a specific subdirectory
func RemoveAll(name string) error {
	r, err := Root()
	if err != nil {
		return err
	}
	if debug {
		return nil
	}
	if filepath.IsAbs(name) {
		err = os.RemoveAll(name)
		return err
	}
	return r.RemoveAll(name)
}

// RemoveRoot removes the entire temp root.
func RemoveRoot() error {
	if debug {
		return nil
	}
	if root == nil {
		return nil
	}
	root.Close()
	err := os.RemoveAll(rootPath)
	return err
}

// CloseRoot for manual
func CloseRoot() error {
	if root != nil {
		return root.Close()
	}
	return nil
}

// setupSignalCleanup automatically cleans temp directory on interrupts.
func setupSignalCleanup() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	go func() {
		<-c
		if !debug && rootPath != "" {
			os.RemoveAll(rootPath)
		}
	}()
}
