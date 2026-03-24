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
	"strings"
	"sync"
	"syscall"
)

var (
	rootDir string
	once    sync.Once
	errInit error
	debug   bool
)

// SetDebug disables automatic cleanup when enabled.
func SetDebug(enabled bool) {
	debug = enabled
}

// initRoot creates the root directory once.
func initRoot() {
	rootDir, errInit = os.MkdirTemp("", "osv-scalibr-run-*")
	if errInit != nil {
		return
	}

	setupSignalCleanup()
}

// Root returns the root directory for the current run.
func Root() (string, error) {
	once.Do(initRoot)
	return rootDir, errInit
}

// CreateDir creates a subdirectory under the root temp directory.
func CreateDir(name string) (string, error) {
	once.Do(initRoot)
	if errInit != nil {
		return "", errInit
	}

	dir, err := resolveUnderRoot(name)
	if err != nil {
		return "", err
	}

	err = os.MkdirAll(dir, 0o755)
	if err != nil {
		return "", fmt.Errorf("failed creating temp dir %s: %w", dir, err)
	}

	return dir, nil
}

// CreateExtractorDir creates a directory for extractor plugins.
// Layout: <SCALIBR-TMP-ROOT>/extractor/<plugin>/<filename>
func CreateExtractorDir(plugin, filename string) (string, error) {
	dir := filepath.Join("extractor", plugin, filepath.Base(filename))
	return CreateDir(dir)
}

// CreateEnricherDir creates a directory for enricher plugins.
// Layout: <SCALIBR-TMP-ROOT>/enricher/<plugin>/<filename>
func CreateEnricherDir(plugin, filename string) (string, error) {
	dir := filepath.Join("enricher", plugin, filepath.Base(filename))
	return CreateDir(dir)
}

// CreateDetectorDir creates a directory for detector plugins.
// Layout: <SCALIBR-TMP-ROOT>/detector/<plugin>/<filename>
func CreateDetectorDir(plugin, filename string) (string, error) {
	dir := filepath.Join("detector", plugin, filepath.Base(filename))
	return CreateDir(dir)
}

// CreateFile creates a temporary file similar to os.CreateTemp,
// but ensures the file is always created under rootDir.
//
// If dir == "":
//
//	-> uses rootDir
//
// If dir != "":
//
//	-> validates it is inside rootDir using resolveUnderRoot
//	-> ensures the directory exists
func CreateFile(dir, pattern string) (string, *os.File, error) {
	once.Do(initRoot)
	if errInit != nil {
		return "", nil, errInit
	}

	var targetDir string
	var err error

	if dir == "" {
		targetDir = rootDir
	} else {
		targetDir, err = resolveUnderRoot(dir)
		if err != nil {
			return "", nil, err
		}

		// Ensure directory exists (important!)
		if err := os.MkdirAll(targetDir, 0o755); err != nil {
			return "", nil, fmt.Errorf("failed to create directory %s: %w", targetDir, err)
		}
	}

	file, err := os.CreateTemp(targetDir, pattern)
	if err != nil {
		return "", nil, fmt.Errorf("failed creating temp file: %w", err)
	}

	return file.Name(), file, nil
}

func resolveUnderRoot(name string) (string, error) {
	var absPath string
	var err error

	if filepath.IsAbs(name) {
		// Already absolute, use directly
		absPath, err = filepath.Abs(name)
		if err != nil {
			return "", err
		}
	} else {
		// Relative, resolve under rootDir
		absPath, err = filepath.Abs(filepath.Join(rootDir, name))
		if err != nil {
			return "", err
		}
	}

	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return "", err
	}

	// Ensure absPath is inside rootDir
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return "", err
	}

	if strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("path escapes root directory: %s", name)
	}

	return absPath, nil
}

// RemoveAll removes a specific subdirectory.
func RemoveAll(name string) error {
	once.Do(initRoot)
	if errInit != nil {
		return errInit
	}

	if debug {
		return nil
	}

	dir, err := resolveUnderRoot(name)
	if err != nil {
		return err
	}

	return os.RemoveAll(dir)
}

// RemoveRoot removes the entire temp root.
func RemoveRoot() error {
	once.Do(initRoot)
	if errInit != nil {
		return errInit
	}

	if debug {
		return nil
	}

	return os.RemoveAll(rootDir)
}

// setupSignalCleanup automatically cleans temp directory on interrupts.
func setupSignalCleanup() {
	c := make(chan os.Signal, 1)

	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)

	go func() {
		<-c
		if !debug && rootDir != "" {
			os.RemoveAll(rootDir)
		}
	}()
}
