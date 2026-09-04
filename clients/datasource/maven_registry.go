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
	"golang.org/x/oauth2/google"
)

// mavenCentral holds the URL of Maven Central Repository.
const mavenCentral = "https://repo.maven.apache.org/maven2"

// artifactRegistryScheme defines the scheme for Google Artifact Registry.
const artifactRegistryScheme = "artifactregistry"

var errAPIFailed = errors.New("API query failed")

// ParseMavenRegistryURL parses a Maven registry URL string that may contain optional origin URLs to
// replace in the format "MIRROR_URL[ORIGIN_URL1,ORIGIN_URL2,...]" or "MIRROR_URL".
// IPv6 URLs without a port or path should include a trailing slash (e.g. "http://[::1]/") to avoid
// the host brackets being treated as replacement origin brackets.
func ParseMavenRegistryURL(raw string) (string, []string) {
	raw = strings.TrimSpace(raw)
	if strings.HasSuffix(raw, "]") {
		if idx := strings.LastIndex(raw, "["); idx != -1 {
			mirror := strings.TrimSpace(raw[:idx])
			originsPart := raw[idx+1 : len(raw)-1]
			var origins []string
			for s := range strings.SplitSeq(originsPart, ",") {
				s = strings.TrimSpace(s)
				if s != "" {
					origins = append(origins, s)
				}
			}
			return mirror, origins
		}
	}
	return raw, nil
}

func normalizeRegistryURL(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimSuffix(raw, "/")
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return strings.TrimSuffix(strings.ToLower(u.Host)+"/"+strings.Trim(strings.ToLower(u.Path), "/"), "/")
	}
	return strings.ToLower(raw)
}

// MavenRegistryAPIClient defines a client to fetch metadata from a Maven registry.
type MavenRegistryAPIClient struct {
	defaultRegistry  MavenRegistry                  // The default registry that we are making requests
	originRegistries map[string]bool                // Normalized origin URLs to be replaced by the default registry
	registries       []MavenRegistry                // Additional registries specified to fetch projects
	registryAuths    map[string]*HTTPAuthentication // Authentication for the registries keyed by registry ID. From settings.xml
	localRegistry    string                         // The local directory that holds Maven manifests
	localProjects    map[maven.ProjectKey][]byte    // Local projects available in the local source tree.

	httpClient        *http.Client // Custom HTTP client for regular queries.
	googleClient      *http.Client // A client for authenticating with Google services, used for Artifact Registry.
	disableGoogleAuth bool         // If true, do not try to create google.DefaultClient for Artifact Registry.

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
func NewMavenRegistryAPIClient(
	ctx context.Context,
	registry MavenRegistry,
	localRegistry string,
	disableGoogleAuth bool,
	httpClient *http.Client,
	googleClient *http.Client,
) (*MavenRegistryAPIClient, error) {
	if httpClient == nil {
		return nil, errors.New("httpClient must be configured for MavenRegistryAPIClient")
	}

	mirrorURL, originURLs := ParseMavenRegistryURL(registry.URL)
	registry.URL = mirrorURL

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

	var originRegistries map[string]bool
	if len(originURLs) > 0 {
		originRegistries = make(map[string]bool, len(originURLs))
		for _, orig := range originURLs {
			originRegistries[normalizeRegistryURL(orig)] = true
		}
	}

	if localRegistry != "" {
		localRegistry = filepath.Join(localRegistry, "maven")
	}

	// TODO: allow for manual specification of settings files
	globalSettings := ParseMavenSettings(globalMavenSettingsFile())
	userSettings := ParseMavenSettings(userMavenSettingsFile())

	client := &MavenRegistryAPIClient{
		// We assume only downloading releases is allowed on the default registry.
		defaultRegistry:   registry,
		originRegistries:  originRegistries,
		localRegistry:     localRegistry,
		mu:                &sync.Mutex{},
		responses:         NewRequestCache[string, response](),
		registryAuths:     MakeMavenAuth(globalSettings, userSettings),
		disableGoogleAuth: disableGoogleAuth,
		httpClient:        httpClient,
		googleClient:      googleClient,
	}
	if registry.Parsed.Scheme == artifactRegistryScheme && googleClient == nil {
		client.createGoogleClient(ctx)
	}
	return client, nil
}

// NewDefaultMavenRegistryAPIClient creates a new MavenRegistryAPIClient with default settings,
// using the provided registry URL.
func NewDefaultMavenRegistryAPIClient(ctx context.Context, registry string) (*MavenRegistryAPIClient, error) {
	return NewMavenRegistryAPIClient(ctx, MavenRegistry{URL: registry, ReleasesEnabled: true}, "", false, &http.Client{}, nil)
}

// AddLocalProject adds a project by its Maven POM contents to the local projects map.
func (m *MavenRegistryAPIClient) AddLocalProject(groupID, artifactID, version string, content []byte) {
	if m.localProjects == nil {
		m.localProjects = make(map[maven.ProjectKey][]byte)
	}
	key := maven.ProjectKey{GroupID: maven.String(groupID), ArtifactID: maven.String(artifactID), Version: maven.String(version)}
	m.localProjects[key] = content
}

// WithoutRegistries makes MavenRegistryAPIClient including its cache but not registries.
func (m *MavenRegistryAPIClient) WithoutRegistries() *MavenRegistryAPIClient {
	return &MavenRegistryAPIClient{
		defaultRegistry:   m.defaultRegistry,
		originRegistries:  m.originRegistries,
		localRegistry:     m.localRegistry,
		mu:                m.mu,
		cacheTimestamp:    m.cacheTimestamp,
		responses:         m.responses,
		registryAuths:     m.registryAuths,
		httpClient:        m.httpClient,
		googleClient:      m.googleClient,
		disableGoogleAuth: m.disableGoogleAuth,
		localProjects:     m.localProjects,
	}
}

// AddRegistry adds the given registry to the list of registries if it has not been added.
func (m *MavenRegistryAPIClient) AddRegistry(ctx context.Context, registry MavenRegistry) error {
	normRepoURL := normalizeRegistryURL(registry.URL)

	isReplaced := false
	if len(m.originRegistries) > 0 && m.originRegistries[normRepoURL] {
		registry.URL = m.defaultRegistry.URL
		// Adopt the default registry's ID so that requests to the replaced mirror
		// do not leak the origin repository's credentials from settings.xml.
		registry.ID = m.defaultRegistry.ID
		isReplaced = true
	}

	if !isReplaced && registry.ID == m.defaultRegistry.ID {
		return m.updateDefaultRegistry(ctx, registry)
	}

	for _, reg := range m.registries {
		if (isReplaced && reg.URL == registry.URL) || reg.ID == registry.ID {
			return nil
		}
	}

	u, err := url.Parse(registry.URL)
	if err != nil {
		return err
	}

	registry.Parsed = u
	m.registries = append(m.registries, registry)
	if registry.Parsed.Scheme == artifactRegistryScheme {
		m.createGoogleClient(ctx)
	}

	return nil
}

func (m *MavenRegistryAPIClient) updateDefaultRegistry(ctx context.Context, registry MavenRegistry) error {
	u, err := url.Parse(registry.URL)
	if err != nil {
		return err
	}
	log.Infof("The default Maven registry is being overwritten from %s to %s", m.defaultRegistry.URL, registry.URL)
	registry.Parsed = u
	m.defaultRegistry = registry
	if registry.Parsed.Scheme == artifactRegistryScheme {
		m.createGoogleClient(ctx)
	}
	return nil
}

// createGoogleClient creates a client for authenticating with Google services.
func (m *MavenRegistryAPIClient) createGoogleClient(ctx context.Context) {
	if m.googleClient != nil || m.disableGoogleAuth {
		return
	}
	// This is the scope that artifact-registry-go-tools uses.
	// https://github.com/GoogleCloudPlatform/artifact-registry-go-tools/blob/main/pkg/auth/auth.go
	client, err := google.DefaultClient(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		// We don't return an error here so that we can fall back to a regular http client.
		log.Warnf("failed to create Google default client, Artifact Registry access will be unavailable: %v", err)
		return
	}
	m.googleClient = client
}

// DisableGoogleAuth prevents the creation of a Google client for authentication purpose.
func (m *MavenRegistryAPIClient) DisableGoogleAuth() {
	m.disableGoogleAuth = true
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
	key := maven.ProjectKey{GroupID: maven.String(groupID), ArtifactID: maven.String(artifactID), Version: maven.String(version)}
	if content, ok := m.localProjects[key]; ok {
		file := io.NopCloser(bytes.NewReader(content))
		defer file.Close()
		var project maven.Project
		if err := NewMavenDecoder(file).Decode(&project); err != nil {
			return maven.Project{}, fmt.Errorf("failed to decode local project content: %w", err)
		}
		return project, nil
	}

	var errs []error
	if !strings.HasSuffix(version, "-SNAPSHOT") {
		for _, registry := range append(m.registries, m.defaultRegistry) {
			if !registry.ReleasesEnabled {
				continue
			}
			project, err := m.getProject(ctx, registry, groupID, artifactID, version, "")
			if err == nil {
				return project, nil
			}
			errs = append(errs, err)
		}

		return maven.Project{}, fmt.Errorf("failed to fetch Maven project %s:%s@%s:\n%w", groupID, artifactID, version, errors.Join(errs...))
	}

	for _, registry := range append(m.registries, m.defaultRegistry) {
		// Fetch version metadata for snapshot versions from the registries enabling that.
		if !registry.SnapshotsEnabled {
			continue
		}
		metadata, err := m.getVersionMetadata(ctx, registry, groupID, artifactID, version)
		if err != nil {
			errs = append(errs, err)
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
		errs = append(errs, err)
	}

	return maven.Project{}, fmt.Errorf("failed to fetch Maven project %s:%s@%s:\n%w", groupID, artifactID, version, errors.Join(errs...))
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

	var project maven.Project
	if err := m.get(ctx, m.registryAuths[registry.ID], registry, []string{strings.ReplaceAll(groupID, ".", "/"), artifactID, version, fmt.Sprintf("%s-%s.pom", artifactID, snapshot)}, &project); err != nil {
		return maven.Project{}, err
	}

	return project, nil
}

// getVersionMetadata fetches a version level maven-metadata.xml and parses it to maven.Metadata.
func (m *MavenRegistryAPIClient) getVersionMetadata(ctx context.Context, registry MavenRegistry, groupID, artifactID, version string) (maven.Metadata, error) {
	var metadata maven.Metadata
	if err := m.get(ctx, m.registryAuths[registry.ID], registry, []string{strings.ReplaceAll(groupID, ".", "/"), artifactID, version, "maven-metadata.xml"}, &metadata); err != nil {
		return maven.Metadata{}, err
	}

	return metadata, nil
}

// GetArtifactMetadata fetches an artifact level maven-metadata.xml and parses it to maven.Metadata.
func (m *MavenRegistryAPIClient) getArtifactMetadata(ctx context.Context, registry MavenRegistry, groupID, artifactID string) (maven.Metadata, error) {
	var metadata maven.Metadata
	if err := m.get(ctx, m.registryAuths[registry.ID], registry, []string{strings.ReplaceAll(groupID, ".", "/"), artifactID, "maven-metadata.xml"}, &metadata); err != nil {
		return maven.Metadata{}, err
	}

	return metadata, nil
}

func (m *MavenRegistryAPIClient) get(ctx context.Context, auth *HTTPAuthentication, registry MavenRegistry, paths []string, dst any) error {
	filePath := ""
	if m.localRegistry != "" {
		filePath = filepath.Join(paths...)
		cacheHit, err := m.readFromCache(filePath, dst)
		if err != nil {
			return err
		}
		if cacheHit {
			return nil
		}
	}

	httpClient := m.httpClient
	requestURL := *registry.Parsed
	isArtifactRegistry := requestURL.Scheme == artifactRegistryScheme
	if isArtifactRegistry {
		requestURL.Scheme = "https"
		// For Artifact Registry, use google.DefaultClient for ADC if available.
		if m.googleClient != nil && !m.disableGoogleAuth {
			httpClient = m.googleClient
		}
	}

	u := requestURL.JoinPath(paths...).String()
	resp, err := m.responses.Get(u, func() (response, error) {
		log.Debugf("Fetching response from: %s", u)
		resp, err := auth.Get(ctx, httpClient, u)
		if err != nil {
			return response{}, fmt.Errorf("%w: Maven registry query failed: %w", errAPIFailed, err)
		}
		defer resp.Body.Close()

		if !slices.Contains([]int{http.StatusOK, http.StatusNotFound, http.StatusUnauthorized, http.StatusForbidden}, resp.StatusCode) {
			// Only cache responses with Status OK, NotFound, Unauthorized, or Forbidden
			return response{}, fmt.Errorf("%w: Maven registry %s query status: %d", errAPIFailed, u, resp.StatusCode)
		}

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return response{}, fmt.Errorf("failed to read body: %w", err)
		}
		if m.localRegistry != "" && resp.StatusCode == http.StatusOK {
			if err := m.writeToCache(filePath, b); err != nil {
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
		if resp.StatusCode == http.StatusForbidden && isArtifactRegistry {
			return fmt.Errorf("%w: Maven registry %s query status: %d (Forbidden). Please check your Application Default Credentials (ADC) have permission to read from %s", errAPIFailed, u, resp.StatusCode, registry.URL)
		}
		return fmt.Errorf("%w: Maven registry %s query status: %d", errAPIFailed, u, resp.StatusCode)
	}

	return NewMavenDecoder(bytes.NewReader(resp.Body)).Decode(dst)
}

func (m *MavenRegistryAPIClient) readFromCache(filePath string, dst any) (bool, error) {
	localRegistryRoot, err := os.OpenRoot(m.localRegistry)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("Error opening local cache %q: %v", m.localRegistry, err)
		}
		return false, nil
	}
	defer localRegistryRoot.Close()

	file, err := localRegistryRoot.Open(filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("Error reading %q from local cache: %v", filePath, err)
		}
		return false, nil
	}
	defer file.Close()

	return true, NewMavenDecoder(file).Decode(dst)
}

func (m *MavenRegistryAPIClient) writeToCache(filePath string, data []byte) error {
	localRegistryRoot, err := os.OpenRoot(m.localRegistry)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(m.localRegistry, 0755); err != nil {
			return fmt.Errorf("failed to create local cache %q: %w", m.localRegistry, err)
		}
		localRegistryRoot, err = os.OpenRoot(m.localRegistry)
	}
	if err != nil {
		return fmt.Errorf("failed to open local cache %q: %w", m.localRegistry, err)
	}
	defer localRegistryRoot.Close()

	return writeFileInRoot(localRegistryRoot, filePath, data)
}

// writeFileInRoot writes the bytes to the file specified by the given path.
func writeFileInRoot(root *os.Root, path string, data []byte) error {
	dir := filepath.Dir(path)
	// Create the directory if it doesn't exist.
	if err := root.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %q: %w", dir, err)
	}

	if err := root.WriteFile(path, data, 0666); err != nil {
		return fmt.Errorf("failed to write file %q: %w", path, err)
	}

	return nil
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
		return fmt.Errorf("failed to create file %q: %w", path, err)
	}
	defer outFile.Close()

	if _, err := outFile.Write(data); err != nil {
		return fmt.Errorf("failed to write file %q: %w", path, err)
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
