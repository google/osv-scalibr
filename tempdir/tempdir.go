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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
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

// PluginType defines the type of plugin for directory layout.
type PluginType string

const (
	// Extractor represents an extraction plugin.
	Extractor PluginType = "extractor"
	// Enricher represents an enrichment plugin.
	Enricher PluginType = "enricher"
	// Detector represents a detection plugin.
	Detector PluginType = "detector"
)

// CreatePluginDir returns a sub-root for a plugin.
// Layout: <SCALIBR-TMP-ROOT>/<pluginType>/<pluginName>/<filename>
func CreatePluginDir(pluginType PluginType, pluginName, filename string) (string, *os.Root, error) {
	dir := filepath.Join(string(pluginType), pluginName, filepath.Base(filename))
	return CreateDir(dir)
}

// CreateFile creates a temp file under the given subRoot using os.Root.
// If subRoot is nil, it uses the global tempdir Root.
func CreateFile(subRoot *os.Root, pattern string) (string, *os.File, error) {
	if subRoot == nil {
		var err error
		subRoot, err = Root()
		if err != nil {
			return "", nil, err
		}
	}

	relDir := "."
	if subRoot != root {
		relDir = subRoot.Name()
	}

	name, f, err := createTemp(subRoot, pattern)
	if err != nil {
		return "", nil, err
	}
	return filepath.Join(rootPath, relDir, name), f, nil
}

func createTemp(subRoot *os.Root, pattern string) (string, *os.File, error) {
	prefix, suffix := prefixAndSuffix(pattern)
	for i := 0; i < 10000; i++ {
		name := prefix + nextRandom() + suffix
		f, err := subRoot.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		return name, f, nil
	}
	return "", nil, errors.New("failed to generate unique temp file")
}

func prefixAndSuffix(pattern string) (prefix, suffix string) {
	if pos := strings.LastIndexByte(pattern, '*'); pos != -1 {
		return pattern[:pos], pattern[pos+1:]
	}
	return pattern, ""
}

func nextRandom() string {
	buf := make([]byte, 4)
	rand.Read(buf)
	return hex.EncodeToString(buf)
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
