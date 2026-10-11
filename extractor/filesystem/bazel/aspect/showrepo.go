// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aspect

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// showRepoBatchSize is the number of repositories queried per "bazel mod show_repo" call, which
// keeps the command line well below OS argument length limits.
const showRepoBatchSize = 200

// repoInfo holds the attributes of the repository rule that fetched an external repository.
type repoInfo struct {
	// RuleName is the repository rule, e.g. "http_archive" or "go_repository".
	RuleName    string
	URLs        []string
	StripPrefix string
	Version     string
	Tag         string
	Commit      string
	Remote      string
	// Importpath is the Go import path of go_repository repositories.
	Importpath string
}

// showRepoAttribute is an attribute in the "bazel mod show_repo --output=streamed_jsonproto"
// output.
type showRepoAttribute struct {
	Name            string   `json:"name"`
	StringValue     string   `json:"stringValue"`
	StringListValue []string `json:"stringListValue"`
}

// showRepoEntry is a repository in the "bazel mod show_repo --output=streamed_jsonproto" output.
type showRepoEntry struct {
	CanonicalName string              `json:"canonicalName"`
	RepoRuleName  string              `json:"repoRuleName"`
	Attribute     []showRepoAttribute `json:"attribute"`
}

// parseShowRepo parses the output of "bazel mod show_repo --output=streamed_jsonproto", a stream
// of JSON objects, into a map keyed by canonical repository name. Entries decoded before an error
// are returned along with the error.
func parseShowRepo(out []byte) (map[string]*repoInfo, error) {
	repos := make(map[string]*repoInfo)
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var e showRepoEntry
		if err := dec.Decode(&e); err != nil {
			if errors.Is(err, io.EOF) {
				return repos, nil
			}
			return repos, err
		}
		if e.CanonicalName == "" {
			continue
		}
		info := &repoInfo{RuleName: e.RepoRuleName}
		for _, a := range e.Attribute {
			switch a.Name {
			case "url":
				if a.StringValue != "" {
					info.URLs = append([]string{a.StringValue}, info.URLs...)
				}
			case "urls":
				info.URLs = append(info.URLs, a.StringListValue...)
			case "strip_prefix":
				info.StripPrefix = a.StringValue
			case "version":
				info.Version = a.StringValue
			case "tag":
				info.Tag = a.StringValue
			case "commit":
				info.Commit = a.StringValue
			case "remote":
				info.Remote = a.StringValue
			case "importpath":
				info.Importpath = a.StringValue
			}
		}
		repos[e.CanonicalName] = info
	}
}

// applyTo fills the empty source attributes of d with the repository rule's attributes.
func (r *repoInfo) applyTo(d *aspectData) {
	fill := func(dst *string, src string) {
		if *dst == "" {
			*dst = src
		}
	}
	if len(r.URLs) > 0 {
		fill(&d.URL, r.URLs[0])
	}
	fill(&d.StripPrefix, r.StripPrefix)
	fill(&d.Version, r.Version)
	fill(&d.Tag, r.Tag)
	fill(&d.Commit, r.Commit)
	fill(&d.Remote, r.Remote)
	fill(&d.Importpath, r.Importpath)
	fill(&d.RepoRule, r.RuleName)
}

// batches splits names into chunks of at most size elements.
func batches(names []string, size int) [][]string {
	var out [][]string
	for len(names) > size {
		out = append(out, names[:size])
		names = names[size:]
	}
	if len(names) > 0 {
		out = append(out, names)
	}
	return out
}

// isGoRepository reports whether the repository was fetched by gazelle's go_repository rule.
func isGoRepository(d *aspectData) bool {
	return d.RepoRule == "go_repository" && d.Importpath != ""
}

// goVersion returns a Go module version in the format used by the other Go extractors, i.e.
// without the "v" prefix.
func goVersion(v string) string {
	return strings.TrimPrefix(v, "v")
}
