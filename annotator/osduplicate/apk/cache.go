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

package apk

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	iofs "io/fs"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk/apkutil"
	"github.com/google/osv-scalibr/fs"
)

const (
	apkCacheDir         = "var/cache/apk/"
	apkRepositoriesPath = "etc/apk/repositories"
)

var (
	// ErrMissingApkCache is returned if the cache folder is missing or empty
	ErrMissingApkCache = errors.New("missing apk cache")

	// alpineRepoRegex matches the strict path structure of an official Alpine OS repo
	alpineRepoRegex = regexp.MustCompile(`\/alpine\/(v\d+\.\d+|edge)\/(main|community|testing)\/?$`)
)

// mainOSPackages contains the set of packages listed in main OS repositories indexes
type mainOSPackages struct {
	value map[string]struct{}
}

// contains returns true if a package found in main OS repo index
func (a *mainOSPackages) contains(pkg *extractor.Package) bool {
	_, exists := a.value[pkg.Name]
	return exists
}

// extractApkCache extracts main repositories information from the var/cache/apk/ folder
func extractApkCache(root *fs.ScanRoot) (*mainOSPackages, error) {
	arch, err := getSystemArch(root)
	if err != nil {
		return nil, fmt.Errorf("failed to get system architecture: %w", err)
	}

	mainRepos, err := listMainRepositories(root)
	if err != nil {
		return nil, err
	}

	res := &mainOSPackages{value: map[string]struct{}{}}
	for _, r := range mainRepos {
		path := getRepoIndexPath(r, arch)
		if err := extractRepositoryIndex(root, path, res); err != nil {
			return nil, err
		}
	}

	return res, nil
}

// getSystemArch reads the architecture from /etc/apk/arch
func getSystemArch(root *fs.ScanRoot) (string, error) {
	file, err := root.FS.Open("etc/apk/arch")
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text()), nil
	}
	return "", errors.New("arch file is empty")
}

// listMainRepositories lists the apk main OS repositories
func listMainRepositories(root *fs.ScanRoot) ([]string, error) {
	content, err := root.FS.Open(apkRepositoriesPath)
	if err != nil {
		return nil, fmt.Errorf("missing apk repositories: %w", err)
	}
	defer content.Close()

	res := []string{}
	scanner := bufio.NewScanner(content)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and commented-out repositories
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if it looks like a standard Alpine OS repository.
		if !alpineRepoRegex.MatchString(line) {
			continue
		}

		res = append(res, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading apk repositories: %w", err)
	}

	return res, nil
}

// getRepoIndexPath returns the repository index path given its url and the system architecture
func getRepoIndexPath(repoURL string, arch string) string {
	fullURL := fmt.Sprintf("%s/%s/APKINDEX.tar.gz", strings.TrimSuffix(repoURL, "/"), arch)
	hashBytes := sha1.Sum([]byte(fullURL))
	hashPrefix := hex.EncodeToString(hashBytes[:])[:8]
	return filepath.Join(apkCacheDir, fmt.Sprintf("APKINDEX.%s.tar.gz", hashPrefix))
}

// extractRepositoryIndex opens the specified cached index file and parses it
func extractRepositoryIndex(root *fs.ScanRoot, filePath string, cache *mainOSPackages) error {
	file, err := root.FS.Open(filePath)
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return errors.Join(ErrMissingApkCache, err)
		}
		return err
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		if header.Name != "APKINDEX" {
			continue
		}

		scanner := apkutil.NewScanner(tr)
		for scanner.Scan() {
			record := scanner.Record()
			if pkgName, ok := record["P"]; ok {
				cache.value[pkgName] = struct{}{}
			}
		}
		return scanner.Err()
	}

	return fmt.Errorf("the repository index: %q doesn't contain any APKINDEX", filePath)
}
