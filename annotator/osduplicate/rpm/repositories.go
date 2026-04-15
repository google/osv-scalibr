// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rpm

import (
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/xml"
	"errors"
	"io"
	iofs "io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	rpmdb "github.com/erikvarga/go-rpmdb/pkg"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scalibr/fs"

	_ "modernc.org/sqlite" // Import sqlite driver
)

const (
	dnfRepoListDir = "var/cache/dnf"
	yumRepoListDir = "var/cache/yum"
)

var (
	// ErrMissingCache is returned if the package manager is properly detected but the cache is missing
	ErrMissingCache = errors.New("rpm cache is empty")
	// ErrMissingOSInfo is returned if there was an error extracting the OS version
	ErrMissingOSInfo = errors.New("unable to extract os information")
)

type mainOSPackages struct {
	vendorOnly     bool
	trustedVendors []string
	value          map[string]struct{}
}

func (m *mainOSPackages) Contains(pkg *rpmdb.PackageInfo) bool {
	if m.vendorOnly {
		return slices.ContainsFunc(m.trustedVendors, func(v string) bool {
			return strings.Contains(pkg.Vendor, v)
		})
	}
	_, exists := m.value[pkg.SourceRpm]
	return exists
}

func extractMainPackages(ctx context.Context, root *fs.ScanRoot) (*mainOSPackages, error) {
	content, err := osrelease.GetOSRelease(root.FS)
	if err != nil {
		return nil, errors.Join(ErrMissingOSInfo, err)
	}
	osID := strings.ToLower(content["ID"])

	// Bypass cache parsing entirely for OS distributions where Vendor matches are reliable
	//
	// Using the Vendor as a mean to classify a package to be from a default repo or not
	// may result in false positives in cases where an rpm package has the same Vendor as other packages
	// published under main repositories while being publish in non default repositories.
	//
	// With RHEL, SLES, openSUSE packages the Vendor seems reliable and is preferred since it doesn't need the cache
	// folder to be refreshed to work.
	switch {
	case osID == "rhel":
		return &mainOSPackages{
			vendorOnly:     true,
			trustedVendors: []string{"Red Hat, Inc."},
		}, nil
	case osID == "sles" || strings.HasPrefix(osID, "sles_") || strings.HasPrefix(osID, "opensuse"):
		return &mainOSPackages{
			vendorOnly:     true,
			trustedVendors: []string{"openSUSE", "SUSE LLC <https://www.suse.com/>"},
		}, nil
	}

	// extract the cache from different folders depending on the installed package manager

	type cacheExtractor struct {
		indicators []string
		// extract given a root and OS id returns a collection of mainOSPackages
		extract func(context.Context, *fs.ScanRoot, string) (*mainOSPackages, error)
	}

	// use config files as indicators to reliably detect the correct package manager
	// since cache folder may be removed
	extractors := []cacheExtractor{
		{indicators: []string{"etc/dnf/dnf.conf"}, extract: extractDnfMainRepos},
		{indicators: []string{"etc/yum/yum.conf", "etc/yum.conf"}, extract: extractYumMainRepos},
		// currently there is no support for zypper since every OS using zypper is handled at Vendor level
	}

	for _, e := range extractors {
		if !hasPackageManager(root, e.indicators) {
			continue
		}
		return e.extract(ctx, root, osID)
	}

	return nil, errors.New("package manager not supported")
}

func hasPackageManager(root *fs.ScanRoot, indicators []string) bool {
	for _, path := range indicators {
		if _, err := iofs.Stat(root.FS, path); err == nil {
			return true
		}
	}
	return false
}

// isMainDnfRepo strictly matches the extracted repo ID based on the OS
func isMainDnfRepo(osID, dirName string) bool {
	// usually repo folder have the following naming structure
	// repo_name-hash
	//
	// The issue is that some repo_name may contain additional info, forcing use to do a broad string check,
	// which makes string manipulation at this point not necessary
	repoID := dirName

	switch osID {
	case "almalinux", "rocky", "centos", "rhel":
		return strings.Contains(repoID, "appstream") ||
			strings.Contains(repoID, "baseos") ||
			strings.Contains(repoID, "crb") ||
			strings.Contains(repoID, "codeready-builder")
	case "amzn":
		return strings.Contains(repoID, "amazonlinux")
	default:
		return strings.Contains(repoID, "appstream") || strings.Contains(repoID, "baseos")
	}
}

func extractDnfMainRepos(ctx context.Context, root *fs.ScanRoot, osID string) (*mainOSPackages, error) {
	entries, err := iofs.ReadDir(root.FS, dnfRepoListDir)
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return nil, ErrMissingCache
		}
		return nil, err
	}

	if len(entries) == 0 {
		return nil, ErrMissingCache
	}

	cache := &mainOSPackages{
		value: make(map[string]struct{}),
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()

		if !isMainDnfRepo(osID, name) {
			continue
		}

		path := filepath.Join(dnfRepoListDir, name, "repodata")

		repoEntries, err := iofs.ReadDir(root.FS, path)
		if err != nil {
			return nil, err
		}

		for _, e := range repoEntries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), "primary.xml.gz") {
				filePath := filepath.Join(path, e.Name())
				// dnf uses the same repository format as zypper (libsolv)
				if err := parseLibsolvRepo(ctx, root.FS, filePath, cache); err != nil {
					return nil, err
				}
			}
		}
	}

	return cache, nil
}

// isMainYumRepo strictly matches the repo directory name based on the OS
func isMainYumRepo(osID, repoID string) bool {
	switch osID {
	case "amzn":
		return repoID == "amzn2-core" || repoID == "amzn-main" || repoID == "amzn-updates"
	case "centos":
		return repoID == "base" || repoID == "updates" || repoID == "repobase"
	default:
		return repoID == "base" || repoID == "updates"
	}
}

func extractYumMainRepos(ctx context.Context, root *fs.ScanRoot, osID string) (*mainOSPackages, error) {
	// initially read the YUM cache dir to detect if it has been pruned
	entries, err := iofs.ReadDir(root.FS, yumRepoListDir)
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return nil, ErrMissingCache
		}
		return nil, err
	}

	if len(entries) == 0 {
		return nil, ErrMissingCache
	}

	cache := &mainOSPackages{
		value: make(map[string]struct{}),
	}

	// YUM caches are nested (e.g. /var/cache/yum/x86_64/7/base/repodata)
	// WalkDir allows us to find primary.sqlite.gz regardless of directory depth.
	err = iofs.WalkDir(root.FS, yumRepoListDir, func(path string, d iofs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), "primary.sqlite.gz") {
			return nil
		}

		cleanPath := strings.TrimPrefix(path, yumRepoListDir+"/")
		parts := strings.Split(cleanPath, "/")

		// Ensure the path has at least arch/version/repo/file
		if len(parts) < 4 {
			return nil
		}

		// The repository name is always safely at index 2 relative to the yum cache root
		repoName := parts[2]

		if !isMainYumRepo(osID, repoName) {
			return nil
		}

		return parseYumRepo(ctx, root.FS, path, cache)
	})

	if err != nil {
		return nil, err
	}

	return cache, nil
}

// parseYumRepo decompresses a YUM primary.sqlite.gz file to disk and queries it.
func parseYumRepo(ctx context.Context, fsys fs.FS, path string, cache *mainOSPackages) error {
	file, err := fsys.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzReader.Close()

	// 1. Create a temporary file because database/sql requires a filepath
	tmpFile, err := os.CreateTemp("", "yum-primary-*.sqlite")
	if err != nil {
		return err
	}
	// Ensure the temp file is deleted when we're done
	defer os.Remove(tmpFile.Name())

	if _, err := io.Copy(tmpFile, gzReader); err != nil {
		tmpFile.Close()
		return err
	}
	tmpFile.Close()

	db, err := sql.Open("sqlite", tmpFile.Name())
	if err != nil {
		return err
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx, "SELECT rpm_sourcerpm FROM packages")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var sourceRpm sql.NullString
		if err := rows.Scan(&sourceRpm); err != nil {
			return err
		}
		if sourceRpm.Valid && sourceRpm.String != "" {
			cache.value[sourceRpm.String] = struct{}{}
		}
	}

	return rows.Err()
}

type rpmPackage struct {
	SourceRPM string `xml:"format>sourcerpm"`
}

// parseLibsolvRepo parses repository information contained in primary.xml.gz files
//
// zypper and dnf share the same underlying cache implementation
func parseLibsolvRepo(ctx context.Context, fsys fs.FS, path string, cache *mainOSPackages) error {
	file, err := fsys.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzReader.Close()

	decoder := xml.NewDecoder(gzReader)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}

		se, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local != "package" {
			continue
		}

		var pkg rpmPackage
		if err := decoder.DecodeElement(&pkg, &se); err != nil {
			return err
		}

		if pkg.SourceRPM != "" {
			cache.value[pkg.SourceRPM] = struct{}{}
		}
	}

	return nil
}
