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
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/google/osv-scalibr/enricher/vulnmatch/osvlocal/internal/vulns"
	"github.com/google/osv-scalibr/extractor"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

type zipDB struct {
	// the name of the database
	Name string
	// the url that the zip archive was downloaded from
	ArchiveURL string
	// whether this database should make any network requests
	Offline bool
	// the path to the zip archive on disk
	StoredAt string
	// the vulnerabilities that are loaded into this database
	Vulnerabilities []*osvschema.Vulnerability
	// User agent to query with
	UserAgent string

	// whether this database only has some of the advisories
	// loaded from the underlying zip file
	Partial bool
}

var errOfflineDatabaseNotFound = errors.New("no offline version of the OSV database is available")

func fetchRemoteArchiveCRC32CHash(ctx context.Context, url string) (uint32, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)

	if err != nil {
		return 0, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("db host returned %s", resp.Status)
	}

	for _, value := range resp.Header.Values("X-Goog-Hash") {
		if after, ok := strings.CutPrefix(value, "crc32c="); ok {
			value = after
			out, err := base64.StdEncoding.DecodeString(value)

			if err != nil {
				return 0, fmt.Errorf("could not decode crc32c= checksum: %w", err)
			}

			return binary.BigEndian.Uint32(out), nil
		}
	}

	return 0, errors.New("could not find crc32c= checksum")
}

func fetchLocalArchiveCRC32CHash(data []byte) uint32 {
	return crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))
}

func (db *zipDB) fetchZip(ctx context.Context) ([]byte, error) {
	cache, err := os.ReadFile(db.StoredAt)

	if db.Offline {
		if err != nil {
			return nil, errOfflineDatabaseNotFound
		}

		return cache, nil
	}

	if err == nil {
		remoteHash, err := fetchRemoteArchiveCRC32CHash(ctx, db.ArchiveURL)

		if err != nil {
			return nil, err
		}

		if fetchLocalArchiveCRC32CHash(cache) == remoteHash {
			return cache, nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, db.ArchiveURL, nil)

	if err != nil {
		return nil, fmt.Errorf("could not retrieve OSV database archive: %w", err)
	}

	if db.UserAgent != "" {
		req.Header.Set("User-Agent", db.UserAgent)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve OSV database archive: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("db host returned %s", resp.Status)
	}

	var body []byte

	body, err = io.ReadAll(resp.Body)

	if err != nil {
		return nil, fmt.Errorf("could not read OSV database archive from response: %w", err)
	}

	err = os.MkdirAll(path.Dir(db.StoredAt), 0750)

	if err == nil {
		//nolint:gosec // being world readable is fine
		err = os.WriteFile(db.StoredAt, body, 0644)
	}

	return body, nil
}

func mightAffectPackages(v *osvschema.Vulnerability, names []string) bool {
	for _, affected := range v.GetAffected() {
		for _, name := range names {
			if affected.GetPackage().GetName() == name {
				return true
			}

			// "name" will be the git repository in the case of the GIT ecosystem
			for _, ran := range affected.GetRanges() {
				if vulns.NormalizeRepo(ran.GetRepo()) == vulns.NormalizeRepo(name) {
					return true
				}
			}
		}
	}

	return false
}

// Loads the given zip file into the database as an OSV.
// It is assumed that the file is JSON and in the working directory of the db
func (db *zipDB) loadZipFile(zipFile *zip.File, names []string) {
	file, err := zipFile.Open()
	if err != nil {
		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return
	}

	vulnerability := &osvschema.Vulnerability{}
	if err := protojson.Unmarshal(content, vulnerability); err != nil {
		return
	}

	// if we have been provided a list of package names, only load advisories
	// that might actually affect those packages, rather than all advisories
	if len(names) == 0 || mightAffectPackages(vulnerability, names) {
		db.Vulnerabilities = append(db.Vulnerabilities, vulnerability)
	}
}

// load fetches a zip archive of the OSV database and loads known vulnerabilities
// from it (which are assumed to be in json files following the OSV spec).
//
// If a list of package names is provided, then only advisories with at least
// one affected entry for a listed package will be loaded.
//
// Internally, the archive is cached along with the date that it was fetched
// so that a new version of the archive is only downloaded if it has been
// modified, per HTTP caching standards.
func (db *zipDB) load(ctx context.Context, names []string) error {
	db.Vulnerabilities = []*osvschema.Vulnerability{}

	body, err := db.fetchZip(ctx)

	if err != nil {
		return err
	}

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return fmt.Errorf("could not read OSV database archive: %w", err)
	}

	// Read all the files from the zip archive
	for _, zipFile := range zipReader.File {
		if !strings.HasSuffix(zipFile.Name, ".json") {
			continue
		}

		db.loadZipFile(zipFile, names)
	}

	return nil
}

func newZippedDB(ctx context.Context, dbBasePath, name, url, userAgent string, offline bool, invs []*extractor.Package) (*zipDB, error) {
	db := &zipDB{
		Name:       name,
		ArchiveURL: url,
		Offline:    offline,
		StoredAt:   path.Join(dbBasePath, name, "all.zip"),
		UserAgent:  userAgent,

		// we only fully load the database if we're not provided a list of packages
		Partial: len(invs) != 0,
	}
	names := make([]string, 0, len(invs))

	// map the packages to their names ahead of loading,
	// to make things simpler and reduce double working
	for _, inv := range invs {
		names = append(names, inv.Name)
	}

	if err := db.load(ctx, names); err != nil {
		return nil, fmt.Errorf("unable to fetch OSV database: %w", err)
	}

	return db, nil
}

// VulnerabilitiesAffectingPackage returns the vulnerabilities that affects the provided package
//
// TODO: Move this to another file.
func VulnerabilitiesAffectingPackage(allVulns []*osvschema.Vulnerability, pkg *extractor.Package) []*osvschema.Vulnerability {
	var vulnerabilities []*osvschema.Vulnerability

	for _, vulnerability := range allVulns {
		if vulnerability.GetWithdrawn() == nil && vulns.IsAffected(vulnerability, pkg) && !vulns.Include(vulnerabilities, vulnerability) {
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return vulnerabilities
}
