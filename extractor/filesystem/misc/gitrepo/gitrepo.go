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

// Package gitrepo extracts Git repository metadata from filesystems.
package gitrepo

import (
	"bufio"
	"context"
	"io"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// DirExtractorName is the name for the directory extractor.
	DirExtractorName = "misc/gitrepo-dirs"
	// FileExtractorName is the name for the file extractor.
	FileExtractorName = "misc/gitrepo-files"
)

// ============================================================================
// DirExtractor
// ============================================================================

// DirExtractor captures standard Git repositories by looking at the .git directory.
type DirExtractor struct{}

// NewDir returns a new DirExtractor.
func NewDir(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &DirExtractor{}, nil
}

// Name returns the name of the extractor.
func (e DirExtractor) Name() string { return DirExtractorName }

// Version returns the version of the extractor.
func (e DirExtractor) Version() int { return 0 }

// Requirements returns the requirements of the extractor.
func (e DirExtractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		ExtractFromDirs: true,
	}
}

// FileRequired returns true if the specified file is a .git directory.
func (e DirExtractor) FileRequired(api filesystem.FileAPI) bool {
	path := filepath.ToSlash(api.Path())
	return filepath.Base(path) == ".git"
}

// Extract extracts the Git repository metadata.
func (e DirExtractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	return extractFromGitDir(input, input.Path)
}

// ============================================================================
// FileExtractor
// ============================================================================

// FileExtractor captures Git submodules by looking at the .git file.
type FileExtractor struct{}

// NewFile returns a new FileExtractor.
func NewFile(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &FileExtractor{}, nil
}

// Name returns the name of the extractor.
func (e FileExtractor) Name() string { return FileExtractorName }

// Version returns the version of the extractor.
func (e FileExtractor) Version() int { return 0 }

// Requirements returns the requirements of the extractor.
func (e FileExtractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		ExtractFromDirs: false,
	}
}

// FileRequired returns true if the specified file is a .git file.
func (e FileExtractor) FileRequired(api filesystem.FileAPI) bool {
	path := filepath.ToSlash(api.Path())
	return filepath.Base(path) == ".git"
}

// Extract extracts the Git repository metadata from a submodule .git file.
func (e FileExtractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	redirectPath, err := parseGitDirFile(input.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}

	dotGitDir := filepath.Clean(filepath.Join(filepath.Dir(input.Path), redirectPath))
	return extractFromGitDir(input, dotGitDir)
}

// parseGitDirFile parses a .git file (submodule pointer) to find the redirected directory.
func parseGitDirFile(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	if scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if after, found := strings.CutPrefix(line, "gitdir:"); found {
			return strings.TrimSpace(after), nil
		}
	}
	return "", scanner.Err()
}

// Unified Extraction Pipeline
// ============================================================================

func extractFromGitDir(input *filesystem.ScanInput, gitDir string) (inventory.Inventory, error) {
	configPath := filepath.ToSlash(filepath.Join(gitDir, "config"))
	cfgFile, err := input.FS.Open(configPath)
	if err != nil {
		return inventory.Inventory{}, err
	}
	defer cfgFile.Close()

	gitCfg, err := gitconfig.ReadConfig(cfgFile)
	if err != nil {
		return inventory.Inventory{}, err
	}

	urls := make(map[string]bool)
	for _, remote := range gitCfg.Remotes {
		for _, u := range remote.URLs {
			normalized := normalizeURL(u)
			if normalized != "" {
				urls[normalized] = true
			}
		}
	}

	if len(urls) == 0 {
		return inventory.Inventory{}, nil
	}

	commitSHA, err := resolveCommitSHA(input)
	if err != nil {
		commitSHA = ""
	}

	var packages []*extractor.Package
	for u := range urls {
		repoName := inferRepoName(u, input.Path)

		pkg := &extractor.Package{
			Name:     repoName,
			PURLType: purl.TypeGeneric,
			Location: extractor.LocationFromPath(input.Path),
			SourceCode: &extractor.SourceCodeIdentifier{
				Repo:   u,
				Commit: commitSHA,
			},
		}

		domain := parseDomain(u)
		if domain == "github.com" || strings.HasSuffix(domain, ".github.com") {
			pkg.PURLType = purl.TypeGithub
		}
		packages = append(packages, pkg)
	}

	return inventory.Inventory{
		Packages: packages,
	}, nil
}

// ============================================================================
// Low-Level Parsers
// ============================================================================

// normalizeURL normalizes a git remote URL to a standard HTTPS format if possible,
// stripping SSH users and .git suffixes.
func normalizeURL(remoteURL string) string {
	if remoteURL == "" {
		return ""
	}

	// Handle SCP-like SSH syntax: git@github.com:foo/bar.git
	if !strings.Contains(remoteURL, "://") && strings.Contains(remoteURL, "@") && strings.Contains(remoteURL, ":") {
		// Strip user
		if atIdx := strings.Index(remoteURL, "@"); atIdx >= 0 {
			remoteURL = remoteURL[atIdx+1:]
		}
		// Replace first colon with slash
		remoteURL = strings.Replace(remoteURL, ":", "/", 1)
		remoteURL = "https://" + remoteURL
	}

	u, err := url.Parse(remoteURL)
	if err != nil {
		return strings.TrimSuffix(remoteURL, ".git")
	}

	if u.Scheme == "ssh" || u.Scheme == "git" || u.Scheme == "http" {
		u.Scheme = "https"
	}

	u.User = nil

	res := u.String()
	return strings.TrimSuffix(res, ".git")
}

var resolveCommitSHA = func(input *filesystem.ScanInput) (string, error) {
	absDotGitDir := filepath.Join(input.Root, input.Path)
	absRepoRoot := filepath.Dir(absDotGitDir)
	repo, err := git.PlainOpen(absRepoRoot)
	if err != nil {
		return "", err
	}
	ref, err := repo.Head()
	if err != nil {
		return "", err
	}
	return ref.Hash().String(), nil
}

func inferRepoName(remoteURL, dotGitDir string) string {
	if remoteURL != "" {
		base := filepath.Base(remoteURL)
		return strings.TrimSuffix(base, ".git")
	}
	parent := filepath.Dir(filepath.Clean(dotGitDir))
	return filepath.Base(parent)
}

// parseDomain extracts the domain name from a git remote URL.
func parseDomain(remoteURL string) string {
	if remoteURL == "" {
		return ""
	}
	if strings.HasPrefix(remoteURL, "/") {
		return ""
	}
	if !strings.Contains(remoteURL, "://") {
		if strings.Contains(remoteURL, "@") && strings.Contains(remoteURL, ":") {
			remoteURL = strings.Replace(remoteURL, ":", "/", 1)
		}
		remoteURL = "https://" + remoteURL
	}
	parsedURL, err := url.Parse(remoteURL)
	if err != nil {
		return ""
	}
	return parsedURL.Hostname()
}
