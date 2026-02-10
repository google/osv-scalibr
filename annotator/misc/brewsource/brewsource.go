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

// Package brewsource provides a way to annotate packages with repository url.
package brewsource

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/os/homebrew/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name of the Annotator
	Name = "misc/brew-source"
)

var vcsPrefixes = [2]string{
	"https://github.com",
	"https://gitlab.com",
}

// Annotator adds repository source code identifiers for extracted Homebrew packages.
// It tries to extract the Git repository URL from the Homebrew package metadata fields: URL, Head, and Mirrors.
type Annotator struct{}

// New returns a new Annotator.
func New(_ *cpb.PluginConfig) (annotator.Annotator, error) { return &Annotator{}, nil }

// Name returns the name of the annotator.
func (Annotator) Name() string { return Name }

// Version returns the version of the annotator.
func (Annotator) Version() int { return 0 }

// Requirements returns the requirements of the annotator.
func (Annotator) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// Annotate adds repository source code identifiers for extracted Homebrew packages.
func (a Annotator) Annotate(ctx context.Context, input *annotator.ScanInput, results *inventory.Inventory) error {
	for _, pkg := range results.Packages {
		// Return if canceled or exceeding deadline.
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%s halted at %q because of context error: %w", a.Name(), input.ScanRoot.Path, err)
		}
		// Only annotate homebrew packages.
		if pkg.PURLType != purl.TypeBrew {
			continue
		}
		md, ok := pkg.Metadata.(*metadata.Metadata)
		if !ok {
			continue
		}
		var repoURL string
		// Try md.URL, then md.Head, then each md.Mirrors until one yields a valid repo URL.
		candidates := append([]string{md.URL, md.Head}, md.Mirrors...)

		for _, c := range candidates {
			if c == "" {
				continue
			}
			if u, err := fetchGitRemoteURL(c); err == nil {
				repoURL = u
				break
			}
		}
		if repoURL != "" {
			pkg.SourceCode = &extractor.SourceCodeIdentifier{
				Repo: repoURL,
			}
		}
	}

	return nil
}

func fetchGitRemoteURL(url string) (string, error) {
	for _, prefix := range vcsPrefixes {
		if !strings.HasPrefix(url, prefix) {
			continue
		}
		// extract the repository URL, for example https://github.com/owner/repo.git
		urlParts := strings.SplitN(url, "/", 6)
		if len(urlParts) < 5 {
			return "", fmt.Errorf("invalid VCS URL: %s", url)
		}
		repoURL := fmt.Sprintf("%s/%s/%s", prefix, urlParts[3], urlParts[4])
		return repoURL, nil
	}
	return "", fmt.Errorf("no VCS prefix found in URL: %s", url)
}
