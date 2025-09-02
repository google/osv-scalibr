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

package datasource

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"deps.dev/util/maven"
	"deps.dev/util/semver"
	"github.com/google/osv-scalibr/log"
	"golang.org/x/net/html/charset"
)

// mavenCentral holds the URL of Maven Central Repository.
const mavenCentral = "https://repo.maven.apache.org/maven2"

var errAPIFailed = errors.New("API query failed")

// MavenRegistryAPIClient defines a client to fetch metadata from a Maven registry.
type MavenRegistryAPIClient struct {
	defaultRegistry MavenRegistry                  // The default registry that we are making requests
	registries      []MavenRegistry                // Additional registries specified to fetch projects
	registryAuths   map[string]*HTTPAuthentication // Authentication for the registries keyed by registry ID. From settings.xml
	localRegistry   string                         // The local directory that holds Maven manifests

	// Cache fields
	mu             *sync.Mutex
	cacheTimestamp *time.Time // If set, this means we loaded from a cache
	responses      *RequestCache[string, response]
}

type response struct {
	StatusCode int
	Body       []byte
}

// MavenRegistry defines a Maven registry.
type MavenRegistry struct {
	URL    string
	Parsed *url.URL

	// Information from pom.xml
	ID               string
	ReleasesEnabled  bool
	SnapshotsEnabled bool
}

// NewMavenRegistryAPIClient returns a new MavenRegistryAPIClient.
func NewMavenRegistryAPIClient(registry MavenRegistry, localRegistry string) (*MavenRegistryAPIClient, error) {
	if registry.URL == "" {
		registry.URL = mavenCentral
		registry.ID = "central"
	}
	if registry.ID == "" {
		// Gives the default registry an ID so it is not overwritten by registry without an ID in pom.xml.
		registry.ID = "default"
	}
	u, err := url.Parse(registry.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid Maven registry %s: %w", registry.URL, err)
	}
	registry.Parsed = u

	// TODO: allow for manual specification of settings files
	globalSettings := ParseMavenSettings(globalMavenSettingsFile())
	userSettings := ParseMavenSettings(userMavenSettingsFile())

	return &MavenRegistryAPIClient{
		// We assume only downloading releases is allowed on the default registry.
		defaultRegistry: registry,
		localRegistry:   localRegistry,
		mu:              &sync.Mutex{},
		responses:       NewRequestCache[string, response](),
		registryAuths:   MakeMavenAuth(globalSettings, userSettings),
	}, nil
}

// SetLocalRegistry sets the local directory that stores the downloaded Maven manifests.
func (m *MavenRegistryAPIClient) SetLocalRegistry(localRegistry string) {
	m.localRegistry = localRegistry
}

// WithoutRegistries makes MavenRegistryAPIClient including its cache but not registries.
func (m *MavenRegistryAPIClient) WithoutRegistries() *MavenRegistryAPIClient {
	return &MavenRegistryAPIClient{
		defaultRegistry: m.defaultRegistry,
		localRegistry:   m.localRegistry,
		mu:              m.mu,
		cacheTimestamp:  m.cacheTimestamp,
		responses:       m.responses,
		registryAuths:   m.registryAuths,
	}
}

// AddRegistry adds the given registry to the list of registries if it has not been added.
func (m *MavenRegistryAPIClient) AddRegistry(registry MavenRegistry) error {
	if registry.ID == m.defaultRegistry.ID {
		return m.updateDefaultRegistry(registry)
	}

	for _, reg := range m.registries {
		if reg.ID == registry.ID {
			return nil
		}
	}

	u, err := url.Parse(registry.URL)
	if err != nil {
		return err
	}

	registry.Parsed = u
	m.registries = append(m.registries, registry)

	return nil
}

func (m *MavenRegistryAPIClient) updateDefaultRegistry(registry MavenRegistry) error {
	u, err := url.Parse(registry.URL)
	if err != nil {
		return err
	}
	registry.Parsed = u
	m.defaultRegistry = registry
	return nil
}

// GetRegistries returns the registries added to this client.
func (m *MavenRegistryAPIClient) GetRegistries() (registries []MavenRegistry) {
	return m.registries
}

// GetProject fetches a pom.xml specified by groupID, artifactID and version and parses it to maven.Project.
// Each registry in the list is tried until we find the project.
// For a snapshot version, version level metadata is used to find the extact version string.
// More about Maven Repository Metadata Model: https://maven.apache.org/ref/3.9.9/maven-repository-metadata/
// More about Maven Metadata: https://maven.apache.org/repositories/metadata.html
func (m *MavenRegistryAPIClient) GetProject(ctx context.Context, groupID, artifactID, version string) (maven.Project, error) {
	if !strings.HasSuffix(version, "-SNAPSHOT") {
		for _, registry := range append(m.registries, m.defaultRegistry) {
			if !registry.ReleasesEnabled {
				continue
			}
			project, err := m.getProject(ctx, registry, groupID, artifactID, version, "")
			if err == nil {
				return project, nil
			}
		}

		return maven.Project{}, fmt.Errorf("failed to fetch Maven project %s:%s@%s", groupID, artifactID, version)
	}

	for _, registry := range append(m.registries, m.defaultRegistry) {
		// Fetch version metadata for snapshot versions from the registries enabling that.
		if !registry.SnapshotsEnabled {
			continue
		}
		metadata, err := m.getVersionMetadata(ctx, registry, groupID, artifactID, version)
		if err != nil {
			continue
		}

		snapshot := ""
		for _, sv := range metadata.Versioning.SnapshotVersions {
			if sv.Extension == "pom" {
				// We only look for pom.xml for project metadata.
				snapshot = string(sv.Value)
				break
			}
		}

		project, err := m.getProject(ctx, registry, groupID, artifactID, version, snapshot)
		if err == nil {
			return project, nil
		}
	}

	return maven.Project{}, fmt.Errorf("failed to fetch Maven project %s:%s@%s", groupID, artifactID, version)
}

// GetVersions returns the list of available versions of a Maven package specified by groupID and artifactID.
// Versions found in all registries are unioned, then sorted by semver.
func (m *MavenRegistryAPIClient) GetVersions(ctx context.Context, groupID, artifactID string) ([]maven.String, error) {
	var versions []maven.String
	for _, registry := range append(m.registries, m.defaultRegistry) {
		metadata, err := m.getArtifactMetadata(ctx, registry, groupID, artifactID)
		if err != nil {
			continue
		}
		versions = append(versions, metadata.Versioning.Versions...)
	}
	slices.SortFunc(versions, func(a, b maven.String) int { return semver.Maven.Compare(string(a), string(b)) })

	return slices.Compact(versions), nil
}

// getProject fetches a pom.xml specified by groupID, artifactID and version and parses it to maven.Project.
// For snapshot versions, the exact version value is specified by snapshot.
func (m *MavenRegistryAPIClient) getProject(ctx context.Context, registry MavenRegistry, groupID, artifactID, version, snapshot string) (maven.Project, error) {
	if snapshot == "" {
		snapshot = version
	}
	log.Infof("Getting project %s:%s version %s (snapshot: %s) from registry %s", groupID, artifactID, version, snapshot, registry.Parsed.String())

	var project maven.Project
	if err := m.get(ctx, m.registryAuths[registry.ID], registry, []string{strings.ReplaceAll(groupID, ".", "/"), artifactID, version, fmt.Sprintf("%s-%s.pom", artifactID, snapshot)}, &project); err != nil {
		return maven.Project{}, err
	}

	return project, nil
}

// getVersionMetadata fetches a version level maven-metadata.xml and parses it to maven.Metadata.
func (m *MavenRegistryAPIClient) getVersionMetadata(ctx context.Context, registry MavenRegistry, groupID, artifactID, version string) (maven.Metadata, error) {
	log.Infof("Getting version metadata for %s:%s@%s from registry %s", groupID, artifactID, version, registry.ID)
	var metadata maven.Metadata
	if err := m.get(ctx, m.registryAuths[registry.ID], registry, []string{strings.ReplaceAll(groupID, ".", "/"), artifactID, version, "maven-metadata.xml"}, &metadata); err != nil {
		return maven.Metadata{}, err
	}

	return metadata, nil
}

// GetArtifactMetadata fetches an artifact level maven-metadata.xml and parses it to maven.Metadata.
func (m *MavenRegistryAPIClient) getArtifactMetadata(ctx context.Context, registry MavenRegistry, groupID, artifactID string) (maven.Metadata, error) {
	log.Infof("Getting artifact metadata for %s:%s from registry %s", groupID, artifactID, registry.Parsed.String())
	var metadata maven.Metadata
	if err := m.get(ctx, m.registryAuths[registry.ID], registry, []string{strings.ReplaceAll(groupID, ".", "/"), artifactID, "maven-metadata.xml"}, &metadata); err != nil {
		return maven.Metadata{}, err
	}

	return metadata, nil
}

func (m *MavenRegistryAPIClient) get(ctx context.Context, auth *HTTPAuthentication, registry MavenRegistry, paths []string, dst any) error {
	filePath := ""
	if m.localRegistry != "" {
		filePath = filepath.Join(append([]string{m.localRegistry}, paths...)...)
		file, err := os.Open(filePath)
		if err == nil {
			defer file.Close()
			// We can still fetch the file from upstream if error is not nil.
			return NewMavenDecoder(file).Decode(dst)
		}
		if !os.IsNotExist(err) {
			log.Warnf("Error reading from local cache %s: %v", filePath, err)
		}
	}

	u := registry.Parsed.JoinPath(paths...).String()
	resp, err := m.responses.Get(u, func() (response, error) {
		resp, err := auth.Get(ctx, http.DefaultClient, u)
		if err != nil {
			return response{}, fmt.Errorf("%w: Maven registry query failed: %w", errAPIFailed, err)
		}
		defer resp.Body.Close()

		if !slices.Contains([]int{http.StatusOK, http.StatusNotFound, http.StatusUnauthorized}, resp.StatusCode) {
			// Only cache responses with Status OK, NotFound, or Unauthorized
			return response{}, fmt.Errorf("%w: Maven registry query status: %d", errAPIFailed, resp.StatusCode)
		}

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return response{}, fmt.Errorf("failed to read body: %w", err)
		}

		if filePath != "" && resp.StatusCode == http.StatusOK {
			if err := writeFile(filePath, b); err != nil {
				log.Warnf("failed to write response to %s: %v", u, err)
			}
		}

		return response{StatusCode: resp.StatusCode, Body: b}, nil
	})
	if err != nil {
		log.Warnf("failed to get response from %s: %v", u, err)
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: Maven registry query status: %d", errAPIFailed, resp.StatusCode)
	}

	return NewMavenDecoder(bytes.NewReader(resp.Body)).Decode(dst)
}

// writeFile writes the bytes to the file specified by the given path.
func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	// Create the directory if it doesn't exist.
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	outFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", path, err)
	}
	defer outFile.Close()

	if _, err := outFile.Write(data); err != nil {
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}

	return nil
}

// NewMavenDecoder returns an xml decoder with CharsetReader and Entity set.
func NewMavenDecoder(reader io.Reader) *xml.Decoder {
	decoder := xml.NewDecoder(reader)
	// Set charset reader for conversion from non-UTF-8 charset into UTF-8.
	decoder.CharsetReader = charset.NewReaderLabel
	// Set HTML entity map for translation between non-standard entity names
	// and string replacements.
	decoder.Entity = xml.HTMLEntity

	return decoder
}
