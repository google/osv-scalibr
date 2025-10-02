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

// Package dpkg provides utilities for interacting with the dpkg package manager database.
package dpkg

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"

	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/fs/diriterate"
)

const (
	infoDirPath = "var/lib/dpkg/info"
)

// ListFilePathIterator is an iterator over all paths found in dpkg .list files.
type ListFilePathIterator struct {
	rootFs            scalibrfs.FS
	dirs              *diriterate.DirIterator
	currentFileReader io.ReadCloser
	currentScanner    *bufio.Scanner
}

// NewListFilePathIterator creates a new iterator over files installed by dpkg.
// The caller is responsible for calling Close() on the returned iterator.
func NewListFilePathIterator(rootFs scalibrfs.FS) (*ListFilePathIterator, error) {
	if _, err := rootFs.Stat(infoDirPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// If info dir doesn't exist, dpkg is not installed or has no package info.
			// Return an iterator that doesn't iterate over any files.
			return &ListFilePathIterator{rootFs: rootFs}, nil
		}
		return nil, err
	}
	dirs, err := diriterate.ReadDir(rootFs, infoDirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read dpkg info dir at %s: %w", infoDirPath, err)
	}
	return &ListFilePathIterator{rootFs: rootFs, dirs: dirs}, nil
}

// Next returns the path of the next installed file.
// It returns io.EOF when there are no more files.
func (it *ListFilePathIterator) Next(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("dpkg.ListFilePathIterator.Next halted because of context error: %w", err)
	}

	for {
		if it.currentScanner != nil && it.currentScanner.Scan() {
			return it.currentScanner.Text(), nil
		}
		if it.currentFileReader != nil {
			it.currentFileReader.Close()
			it.currentFileReader = nil
			it.currentScanner = nil
		}

		listPath, err := it.nextListFile()
		if err != nil {
			return "", err
		}

		reader, err := it.rootFs.Open(listPath)
		if err != nil {
			return "", err
		}
		it.currentFileReader = reader
		it.currentScanner = bufio.NewScanner(reader)
	}
}

func (it *ListFilePathIterator) nextListFile() (string, error) {
	if it.dirs == nil {
		return "", io.EOF
	}
	for {
		f, err := it.dirs.Next()
		if err != nil {
			return "", err
		}

		if !f.IsDir() && path.Ext(f.Name()) == ".list" {
			return path.Join(infoDirPath, f.Name()), nil
		}
	}
}

// Close closes the iterator and releases any resources.
func (it *ListFilePathIterator) Close() error {
	var errs []error
	if it.currentFileReader != nil {
		if err := it.currentFileReader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if it.dirs != nil {
		if err := it.dirs.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
