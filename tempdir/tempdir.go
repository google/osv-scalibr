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
	root       *os.Root
	errRoot    error
	once       sync.Once
	debug      bool
	subRoots   []*os.Root
	subRootsMu sync.Mutex
)

// SetDebug disables automatic cleanup when enabled.
func SetDebug(enabled bool) {
	debug = enabled
}

// initRoot creates the root directory once.
func initRoot() {
	path, err := os.MkdirTemp("", "osv-scalibr-run-*")
	if err != nil {
		errRoot = err
		return
	}
	root, errRoot = os.OpenRoot(path)
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
	return root.Name(), nil
}

// CreateDir creates and opens a subdirectory as a new os.Root (chroot-like).
// The caller is responsible for closing the returned *os.Root when it is no longer needed.
func CreateDir(name string) (*os.Root, error) {
	r, err := Root()
	if err != nil {
		return nil, err
	}
	if filepath.IsAbs(name) {
		var err error
		name, err = filepath.Rel(r.Name(), name)
		if err != nil {
			return nil, err
		}
	}
	// Ensure dir exists
	if err := r.MkdirAll(name, 0o755); err != nil && !os.IsExist(err) {
		return nil, err
	}

	newRoot, err := r.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	subRootsMu.Lock()
	subRoots = append(subRoots, newRoot)
	subRootsMu.Unlock()
	return newRoot, nil
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
// The caller is responsible for closing the returned *os.Root when it is no longer needed.
func CreatePluginDir(pluginType PluginType, pluginName, filename string) (*os.Root, error) {
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

	name, f, err := createTemp(subRoot, pattern)
	if err != nil {
		return "", nil, err
	}

	return filepath.Join(subRoot.Name(), name), f, nil
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

// Stat returns the FileInfo for a file relative to the temp root.
func Stat(name string) (os.FileInfo, error) {
	r, err := Root()
	if err != nil {
		return nil, err
	}
	return r.Stat(name)
}

// RemoveAll removes a path relative to the temp root.
func RemoveAll(name string) error {
	r, err := Root()
	if err != nil {
		return err
	}
	if debug {
		return nil
	}
	return r.RemoveAll(name)
}

// RemoveRoot removes the entire temp root after closing all subroots.
func RemoveRoot() error {
	if debug {
		return nil
	}
	subRootsMu.Lock()
	for _, sr := range subRoots {
		if sr != nil {
			_ = sr.Close()
		}
	}
	subRoots = nil
	subRootsMu.Unlock()

	var err error
	if root != nil {
		path := root.Name()
		root.Close()
		root = nil
		err = os.RemoveAll(path)
	}
	once = sync.Once{} // Reset once for subsequent tests
	return err
}

// setupSignalCleanup automatically cleans temp directory on interrupts.
func setupSignalCleanup() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	go func() {
		<-c
		_ = RemoveRoot()
	}()
}
