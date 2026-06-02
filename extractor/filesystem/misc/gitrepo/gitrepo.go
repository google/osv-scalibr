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
	"context"
	"net/url"
	"path"
	"path/filepath"
	"strings"

	gitconfig "github.com/go-git/go-git/v5/config"

	"github.com/go-git/go-git/v5"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "misc/gitrepo"
)

// Extractor captures standard Git repositories by looking at the .git directory
// and programmatically walking its submodules.
type Extractor struct{}

// New returns a new Extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &Extractor{}, nil
}

// Name returns the name of the extractor.
func (e Extractor) Name() string { return Name }

// Version returns the version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements returns the requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		ExtractFromDirs: true,
		DirectFS:        true,
	}
}

// FileRequired returns true if the specified file is a .git directory.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return path.Base(api.Path()) == ".git"
}

// Extract extracts the Git repository metadata including submodules.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	return extractFromGitDir(input)
}

// ============================================================================
// Unified Extraction Pipeline
// ============================================================================

func extractFromGitDir(input *filesystem.ScanInput) (inventory.Inventory, error) {
	absDotGitDir := filepath.Join(input.Root, filepath.FromSlash(input.Path))
	absRepoRoot := filepath.Dir(absDotGitDir)

	repo, plainOpenErr := git.PlainOpen(absRepoRoot)

	urls := make(map[string]bool)
	commitSHA := ""

	if plainOpenErr == nil {
		remotes, err := repo.Remotes()
		if err != nil {
			return inventory.Inventory{}, err
		}
		for _, remote := range remotes {
			cfg := remote.Config()
			if cfg != nil {
				for _, u := range cfg.URLs {
					normalized := normalizeURL(u)
					if normalized != "" {
						urls[normalized] = true
					}
				}
			}
		}
		if ref, err := repo.Head(); err == nil {
			commitSHA = ref.Hash().String()
		}
	} else {
		// Fallback for missing HEAD or other PlainOpen failures
		configPath := path.Join(input.Path, "config")
		cfgFile, err := input.FS.Open(configPath)
		if err != nil {
			return inventory.Inventory{}, plainOpenErr
		}
		defer cfgFile.Close()

		gitCfg, err := gitconfig.ReadConfig(cfgFile)
		if err != nil {
			return inventory.Inventory{}, err
		}

		for _, remote := range gitCfg.Remotes {
			for _, u := range remote.URLs {
				normalized := normalizeURL(u)
				if normalized != "" {
					urls[normalized] = true
				}
			}
		}
	}

	if len(urls) == 0 {
		return inventory.Inventory{}, nil
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

	if plainOpenErr == nil {
		visited := make(map[string]bool)
		packages = append(packages, extractSubmodules(repo, absRepoRoot, path.Dir(input.Path), visited)...)
	}

	return inventory.Inventory{
		Packages: packages,
	}, nil
}

func extractSubmodules(repo *git.Repository, absRepoRoot, relativePath string, visited map[string]bool) []*extractor.Package {
	if visited[absRepoRoot] {
		return nil
	}
	visited[absRepoRoot] = true

	wt, err := repo.Worktree()
	if err != nil {
		return nil
	}

	submodules, err := wt.Submodules()
	if err != nil {
		return nil
	}

	var packages []*extractor.Package
	for _, sub := range submodules {
		cfg := sub.Config()
		if cfg == nil {
			continue
		}

		subSHA := ""
		status, err := sub.Status()
		if err == nil {
			subSHA = status.Expected.String()
			if subSHA == "0000000000000000000000000000000000000000" {
				subSHA = ""
			}
		}

		normalizedSubURL := normalizeURL(cfg.URL)
		if normalizedSubURL == "" {
			continue
		}

		subPkg := &extractor.Package{
			Name:     inferRepoName(normalizedSubURL, cfg.Path),
			PURLType: purl.TypeGeneric,
			Location: extractor.LocationFromPath(filepath.ToSlash(filepath.Join(relativePath, cfg.Path))),
			SourceCode: &extractor.SourceCodeIdentifier{
				Repo:   normalizedSubURL,
				Commit: subSHA,
			},
		}

		domain := parseDomain(normalizedSubURL)
		if domain == "github.com" || strings.HasSuffix(domain, ".github.com") {
			subPkg.PURLType = purl.TypeGithub
		}
		packages = append(packages, subPkg)

		// Recursive call for nested submodules
		if subRepo, err := sub.Repository(); err == nil {
			// Compute the absolute path of the submodule directory.
			absSubRoot := filepath.Join(absRepoRoot, filepath.FromSlash(cfg.Path))
			subRelativePath := path.Join(relativePath, cfg.Path)
			packages = append(packages, extractSubmodules(subRepo, absSubRoot, subRelativePath, visited)...)
		}
	}

	return packages
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

func inferRepoName(remoteURL, dotGitDir string) string {
	if remoteURL != "" {
		base := path.Base(remoteURL)
		return strings.TrimSuffix(base, ".git")
	}
	parent := path.Dir(path.Clean(dotGitDir))
	return path.Base(parent)
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
