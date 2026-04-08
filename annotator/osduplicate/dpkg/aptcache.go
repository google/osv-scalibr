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

package dpkg

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	iofs "io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/fs"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

// mainRepoPattern matches files containing main OS repositories indexes
var mainRepoPattern = regexp.MustCompile(`[\w.]+(?:-[\w%-]+)?_dists_[\w-]+_main_binary-\w+_Packages(?:\.gz|.lz4|.zst)?$`)

const aptListDir = "var/lib/apt/lists"

// aptCache contains the set of packages listed in main OS repositories indexes
type aptCache struct {
	value map[string]struct{}
}

// isFromMainOSRepo returns true if a package found in main OS repo index
func (a *aptCache) isFromMainOSRepo(pkgName string) bool {
	_, exists := a.value[pkgName]
	return exists
}

// ErrMissingAptCache is returned if the cache folder is missing or empty
var ErrMissingAptCache = errors.New("missing apt cache folder: " + aptListDir)

// extractAptCache extracts main repositories information from the var/lib/apt/lists folder
// if the var/lib/apt/lists folder is empty or doesn't exists it returns errorMissingAptCache
func extractAptCache(root *fs.ScanRoot) (*aptCache, error) {
	entries, err := iofs.ReadDir(root.FS, aptListDir)
	if err != nil {
		// if the `var/lib/apt/lists` doesn't exists which could happen for 2 reasons:
		// - the folder was deleted after installation
		// - apt is not installed
		if errors.Is(err, iofs.ErrNotExist) {
			return nil, ErrMissingAptCache
		}
		return nil, err
	}

	if len(entries) == 0 {
		return nil, ErrMissingAptCache
	}

	cache := &aptCache{
		value: make(map[string]struct{}),
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()

		// skip other repositories' indexes
		if !mainRepoPattern.MatchString(name) {
			continue
		}

		if err := parseAptList(root.FS, filepath.Join(aptListDir, name), cache); err != nil {
			return nil, err
		}
	}

	return cache, nil
}

// parseAptList opens and parses a single apt list file, updating the cache.
func parseAptList(fileSystem iofs.FS, path string, cache *aptCache) error {
	f, err := fileSystem.Open(path)
	if err != nil {
		return nil // Skip files we can't open
	}
	defer f.Close()

	reader, err := readerFromExtension(f, path)
	if err != nil {
		return err
	}
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Bytes()
		// Check if the start of this line contains a package name
		if after, ok := bytes.CutPrefix(line, []byte("Package: ")); ok {
			cache.value[string(after)] = struct{}{}
		}
	}

	return scanner.Err()
}

// readerFromExtension returns an io.ReadCloser depending on the file extension
func readerFromExtension(f iofs.File, name string) (io.ReadCloser, error) {
	switch {
	case strings.HasSuffix(name, ".lz4"):
		return io.NopCloser(lz4.NewReader(f)), nil
	case strings.HasSuffix(name, ".gz"):
		return gzip.NewReader(f)
	case strings.HasSuffix(name, ".zst"):
		r, err := zstd.NewReader(f)
		return io.NopCloser(r), err
	default:
		return io.NopCloser(f), nil
	}
}
