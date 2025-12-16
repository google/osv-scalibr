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

package osvlocal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/google/osv-scalibr/extractor"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const envKeyLocalDBCacheDirectory = "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"

// localMatcher implements the VulnerabilityMatcher interface by downloading the osv export zip files,
// and performing the matching locally.
type localMatcher struct {
	zippedDBRemoteHost string

	dbBasePath string
	dbs        map[osvconstants.Ecosystem]*zipDB
	downloadDB bool
	// failedDBs keeps track of the errors when getting databases for each ecosystem
	failedDBs map[osvconstants.Ecosystem]error
	// userAgent sets the user agent requests for db zips are made with
	userAgent string
}

func newlocalMatcher(localDBPath string, userAgent string, downloadDB bool, zippedDBRemoteHost string) (*localMatcher, error) {
	dbBasePath, err := setupLocalDBDirectory(localDBPath)
	if err != nil {
		return nil, fmt.Errorf("could not create %s: %w", dbBasePath, err)
	}

	return &localMatcher{
		zippedDBRemoteHost: zippedDBRemoteHost,

		dbBasePath: dbBasePath,
		dbs:        make(map[osvconstants.Ecosystem]*zipDB),
		downloadDB: downloadDB,
		userAgent:  userAgent,
		failedDBs:  make(map[osvconstants.Ecosystem]error),
	}, nil
}

func (matcher *localMatcher) MatchVulnerabilities(ctx context.Context, pkg *extractor.Package, pkgs []*extractor.Package) ([]*osvschema.Vulnerability, error) {
	// ensure all databases loaded so far have been fully loaded; this is just a
	// basic safeguard since we don't actually currently attempt to reuse matchers
	// across scans, and its possible we never will, so we don't need to be smart
	// for _, db := range matcher.dbs {
	// 	if db.Partial {
	// 		return nil, errors.New("local matcher cannot be (re)used with a partially loaded database")
	// 	}
	// }

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	eco := pkg.Ecosystem().Ecosystem

	if pkg.Ecosystem().IsEmpty() {
		if pkg.SourceCode != nil && pkg.SourceCode.Commit == "" {
			// This should never happen, as those results will be filtered out before matching
			return nil, errors.New("ecosystem is empty and there is no commit hash")
		}

		// matching ecosystem-less versions can only be attempted if we have a version
		if pkg.Version == "" {
			// Is a commit based query, skip local scanning
			return nil, nil
		}

		eco = "GIT"
	}

	db, err := matcher.loadDBFromCache(ctx, eco, pkgs)

	if err != nil {
		return nil, err
	}

	return VulnerabilitiesAffectingPackage(db.Vulnerabilities, pkg), nil
}

func (matcher *localMatcher) loadDBFromCache(ctx context.Context, eco osvconstants.Ecosystem, invs []*extractor.Package) (*zipDB, error) {
	if db, ok := matcher.dbs[eco]; ok {
		return db, nil
	}

	if matcher.failedDBs[eco] != nil {
		return nil, matcher.failedDBs[eco]
	}

	db, err := newZippedDB(
		ctx,
		matcher.dbBasePath,
		string(eco),
		fmt.Sprintf("%s/%s/all.zip", matcher.zippedDBRemoteHost, eco),
		matcher.userAgent,
		!matcher.downloadDB,
		invs,
	)

	if err != nil {
		matcher.failedDBs[eco] = err

		return nil, err
	}

	matcher.dbs[eco] = db

	return db, nil
}

// setupLocalDBDirectory attempts to set up the directory the scanner should
// use to store local databases.
//
// if a local path is explicitly provided either by the localDBPath parameter
// or via the envKeyLocalDBCacheDirectory environment variable, the scanner will
// attempt to use the user cache directory if possible or otherwise the temp directory
//
// if an error occurs at any point when a local path is not explicitly provided,
// the scanner will fall back to the temp directory first before finally erroring
func setupLocalDBDirectory(localDBPath string) (string, error) {
	var err error

	// fallback to the env variable if a local database path has not been provided
	if localDBPath == "" {
		if p, envSet := os.LookupEnv(envKeyLocalDBCacheDirectory); envSet {
			localDBPath = p
		}
	}

	implicitPath := localDBPath == ""

	// if we're implicitly picking a path, use the user cache directory if available
	if implicitPath {
		localDBPath, err = os.UserCacheDir()

		if err != nil {
			localDBPath = os.TempDir()
		}
	}

	altPath := path.Join(localDBPath, "osv-scanner")
	err = os.MkdirAll(altPath, 0750)
	if err == nil {
		return altPath, nil
	}

	// if we're implicitly picking a path, try the temp directory before giving up
	if implicitPath && localDBPath != os.TempDir() {
		return setupLocalDBDirectory(os.TempDir())
	}

	return "", err
}
