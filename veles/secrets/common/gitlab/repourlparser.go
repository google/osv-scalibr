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

// Package gitlab provides common utilities for GitLab-related secret detection.
package gitlab

import (
	"net/url"
	"strings"
)

// RepoInfo holds parsed repository information from a GitLab URL.
type RepoInfo struct {
	// Scheme is the URL scheme (e.g., "https", "http", "ssh", or "git" for scp-style)
	Scheme string
	// Host is the GitLab hostname (e.g., "gitlab.com", "gitlab.example.com")
	Host string
	// Namespace is the full group/subgroup path (e.g., "org/backend")
	Namespace string
	// Project is the project name (e.g., "api-service")
	Project string
	// FullPath is the complete repository path: namespace/project (e.g., "org/backend/api-service")
	FullPath string
}

// ParseRepoURL extracts scheme, hostname, namespace, and project from a GitLab repository URL.
// Supports both HTTPS and SSH formats:
// - HTTPS: https://gitlab.com/org/backend/api-service.git
// - HTTP: http://gitlab.example.com/org/backend/api-service.git
// - SSH (scp-style): git@gitlab.com:org/backend/api-service.git
// - SSH (URL-style): ssh://git@gitlab.com/org/backend/api-service.git
//
// Returns nil if the URL cannot be parsed or doesn't contain at least a namespace and project.
func ParseRepoURL(rawURL string) *RepoInfo {
	var scheme, hostname, repoPath string

	// Handle SSH scp-style format: git@hostname:path/to/repo.git
	if strings.HasPrefix(rawURL, "git@") {
		scheme = "git"
		parts := strings.SplitN(rawURL[4:], ":", 2) // Remove "git@" and split on ":"
		if len(parts) != 2 {
			return nil
		}
		hostname = parts[0]
		repoPath = parts[1]
	} else {
		// Handle URL formats: https://, http://, ssh://
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil
		}
		scheme = u.Scheme
		hostname = u.Host
		repoPath = strings.TrimPrefix(u.Path, "/")
	}

	// Remove .git suffix
	repoPath = strings.TrimSuffix(repoPath, ".git")

	// Split path into segments
	segments := strings.Split(repoPath, "/")
	if len(segments) < 2 {
		return nil
	}

	// Last segment is the project, everything before is the namespace
	project := segments[len(segments)-1]
	namespace := strings.Join(segments[:len(segments)-1], "/")
	fullPath := repoPath

	return &RepoInfo{
		Scheme:    scheme,
		Host:      hostname,
		Namespace: namespace,
		Project:   project,
		FullPath:  fullPath,
	}
}
