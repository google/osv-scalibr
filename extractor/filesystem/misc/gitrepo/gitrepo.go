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
	"io/fs"
	"net/url"
	"path"
	"path/filepath"
	"strings"

	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/format/index"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
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
	dotGitPath := filepath.ToSlash(input.Path)
	configPath := path.Join(dotGitPath, "config")
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

	commitSHA := resolveHeadCommit(input.FS, dotGitPath)

	var packages []*extractor.Package
	for u := range urls {
		repoName := inferRepoName(u, input.Path)

		pkg := &extractor.Package{
			Name:     repoName,
			Version:  commitSHA,
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

	visited := make(map[string]bool)
	packages = append(packages, extractSubmodules(input.FS, dotGitPath, path.Dir(dotGitPath), visited)...)

	return inventory.Inventory{
		Packages: packages,
	}, nil
}

func isCleanRelPath(p string) bool {
	if p == "" || p == "." || strings.HasPrefix(p, "/") || strings.Contains(p, `\`) {
		return false
	}
	cleaned := path.Clean(p)
	return cleaned == p && cleaned != ".." && !strings.HasPrefix(cleaned, "../")
}

func isHexHash(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func resolveHeadCommit(fsys scalibrfs.FS, dotGitPath string) string {
	if dotGitPath == "" || !isCleanRelPath(dotGitPath) {
		return ""
	}
	headBytes, err := fs.ReadFile(fsys, path.Join(dotGitPath, "HEAD"))
	if err != nil {
		return ""
	}
	head := strings.TrimSpace(string(headBytes))
	if strings.HasPrefix(head, "ref:") {
		refName := strings.TrimSpace(strings.TrimPrefix(head, "ref:"))
		if !isCleanRelPath(refName) {
			return ""
		}
		if refBytes, err := fs.ReadFile(fsys, path.Join(dotGitPath, refName)); err == nil {
			sha := strings.TrimSpace(string(refBytes))
			if isHexHash(sha) {
				return sha
			}
		}
		if packedBytes, err := fs.ReadFile(fsys, path.Join(dotGitPath, "packed-refs")); err == nil {
			return resolvePackedRef(string(packedBytes), refName)
		}
		return ""
	}
	if isHexHash(head) {
		return head
	}
	return ""
}

func resolvePackedRef(content, targetRef string) string {
	var matchedSHA string
	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "^") {
			continue
		}
		spaceIdx := strings.IndexByte(line, ' ')
		if spaceIdx <= 0 {
			return ""
		}
		sha := line[:spaceIdx]
		ref := strings.TrimSpace(line[spaceIdx+1:])
		if !isHexHash(sha) || ref == "" {
			return ""
		}
		if ref == targetRef {
			matchedSHA = sha
		}
	}
	return matchedSHA
}

func extractSubmodules(fsys scalibrfs.FS, dotGitPath, relativePath string, visited map[string]bool) []*extractor.Package {
	if visited[relativePath] {
		return nil
	}
	visited[relativePath] = true

	gitmodulesPath := ".gitmodules"
	if relativePath != "." && relativePath != "" {
		gitmodulesPath = path.Join(relativePath, ".gitmodules")
	}
	if !isCleanRelPath(gitmodulesPath) {
		return nil
	}

	modulesBytes, err := fs.ReadFile(fsys, gitmodulesPath)
	if err != nil {
		return nil
	}

	modules := gitconfig.NewModules()
	if err := modules.Unmarshal(modulesBytes); err != nil {
		return nil
	}

	var idx *index.Index
	indexLoaded := false

	var packages []*extractor.Package
	for _, sub := range modules.Submodules {
		if sub == nil || sub.Validate() != nil {
			continue
		}
		subRelFromRepo := filepath.ToSlash(sub.Path)
		if !isCleanRelPath(subRelFromRepo) {
			continue
		}

		normalizedSubURL := normalizeURL(sub.URL)
		if normalizedSubURL == "" {
			continue
		}

		subRelativePath := subRelFromRepo
		if relativePath != "." && relativePath != "" {
			subRelativePath = path.Join(relativePath, subRelFromRepo)
		}
		if !isCleanRelPath(subRelativePath) {
			continue
		}

		subDotGit := resolveSubmoduleGitDir(fsys, dotGitPath, subRelativePath, filepath.ToSlash(sub.Name))
		subSHA := resolveHeadCommit(fsys, subDotGit)
		if subSHA == "" {
			if !indexLoaded && isCleanRelPath(dotGitPath) {
				indexLoaded = true
				if idxFile, err := fsys.Open(path.Join(dotGitPath, "index")); err == nil {
					var parsedIdx index.Index
					if err := index.NewDecoder(idxFile).Decode(&parsedIdx); err == nil {
						idx = &parsedIdx
					}
					_ = idxFile.Close()
				}
			}
			if idx != nil {
				if entry, err := idx.Entry(subRelFromRepo); err == nil && entry != nil && !entry.Hash.IsZero() {
					subSHA = entry.Hash.String()
				}
			}
		}

		subPkg := &extractor.Package{
			Name:     inferRepoName(normalizedSubURL, subRelFromRepo),
			Version:  subSHA,
			PURLType: purl.TypeGeneric,
			Location: extractor.LocationFromPath(subRelativePath),
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

		if subDotGit != "" {
			packages = append(packages, extractSubmodules(fsys, subDotGit, subRelativePath, visited)...)
		}
	}

	return packages
}

func resolveSubmoduleGitDir(fsys scalibrfs.FS, parentDotGit, subRelativePath, subName string) string {
	candidateDotGit := path.Join(subRelativePath, ".git")
	if info, err := fs.Stat(fsys, candidateDotGit); err == nil {
		if info.IsDir() {
			return candidateDotGit
		}
		if data, err := fs.ReadFile(fsys, candidateDotGit); err == nil {
			line := strings.TrimSpace(string(data))
			if strings.HasPrefix(line, "gitdir:") {
				target := strings.TrimSpace(strings.TrimPrefix(line, "gitdir:"))
				if !strings.HasPrefix(target, "/") {
					resolved := path.Clean(path.Join(subRelativePath, filepath.ToSlash(target)))
					if isCleanRelPath(resolved) {
						if info, err := fs.Stat(fsys, resolved); err == nil && info.IsDir() {
							return resolved
						}
					}
				}
			}
		}
	}
	if isCleanRelPath(parentDotGit) && isCleanRelPath(subName) {
		modDir := path.Join(parentDotGit, "modules", subName)
		if info, err := fs.Stat(fsys, modDir); err == nil && info.IsDir() {
			return modDir
		}
	}
	return ""
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
