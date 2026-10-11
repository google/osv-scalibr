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

package aspect

import (
	"encoding/json"
	"slices"
	"strings"
)

// modGraphNode is a node of the output of `bazel mod graph --output=json`.
type modGraphNode struct {
	Name                 string         `json:"name"`
	Version              string         `json:"version"`
	Root                 bool           `json:"root"`
	Dependencies         []modGraphNode `json:"dependencies"`
	IndirectDependencies []modGraphNode `json:"indirectDependencies"`
}

// moduleVersions maps Bazel module names to the versions present in the resolved module graph.
type moduleVersions map[string][]string

// parseModGraph parses the output of `bazel mod graph --output=json`.
func parseModGraph(data []byte) (moduleVersions, error) {
	var root modGraphNode
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	mv := make(moduleVersions)
	var walk func(n *modGraphNode)
	walk = func(n *modGraphNode) {
		if !n.Root && n.Name != "" && n.Version != "" && !slices.Contains(mv[n.Name], n.Version) {
			mv[n.Name] = append(mv[n.Name], n.Version)
		}
		for i := range n.Dependencies {
			walk(&n.Dependencies[i])
		}
		for i := range n.IndirectDependencies {
			walk(&n.IndirectDependencies[i])
		}
	}
	walk(&root)
	return mv, nil
}

// splitModuleRepoName splits the canonical name of a repository generated for a Bazel module
// (e.g. "grpc+", "grpc~", "grpc~1.74.1" or "grpc+1.74.1" under multiple_version_override) into the
// module name and the version suffix, which is usually empty. ok is false for repositories that
// don't belong to a module, e.g. module extension repos ("gazelle++go_deps+com_github_foo").
func splitModuleRepoName(canonical string) (module, suffix string, ok bool) {
	i := strings.IndexAny(canonical, "+~")
	if i <= 0 {
		return "", "", false
	}
	suffix = canonical[i+1:]
	if strings.ContainsAny(suffix, "+~") {
		return "", "", false
	}
	return canonical[:i], suffix, true
}

// lookup returns the module name and version for the canonical name of a module repository, or
// ok=false if the repository doesn't belong to a module in the graph.
func (mv moduleVersions) lookup(canonical string) (module, version string, ok bool) {
	module, suffix, ok := splitModuleRepoName(canonical)
	if !ok {
		return "", "", false
	}
	versions, inGraph := mv[module]
	switch {
	case !inGraph:
		return "", "", false
	case slices.Contains(versions, suffix):
		return module, suffix, true
	case len(versions) == 1:
		return module, versions[0], true
	}
	// Several versions of the module and none matches the repo name.
	return module, "", true
}
