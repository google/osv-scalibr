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

package archive

import (
	"archive/zip"
	"bufio"
	"fmt"
	"strings"

	"github.com/google/osv-scalibr/log"
)

// PomProps for identifying Maven package.
type PomProps struct {
	GroupID    string
	ArtifactID string
	Version    string
}

// valid returns true if p is a valid pom property.
func (p PomProps) valid() bool {
	return p.GroupID != "" && !strings.Contains(p.GroupID, " ") && p.ArtifactID != "" && !strings.Contains(p.ArtifactID, " ") && p.Version != "" && !strings.Contains(p.Version, " ")
}

func parsePomProps(f *zip.File) (PomProps, error) {
	p := PomProps{}
	file, err := f.Open()
	if err != nil {
		return p, fmt.Errorf("failed to open file %q: %w", f.Name, err)
	}
	defer file.Close()

	log.Debugf("Parsing pom.properties file %s\n", f.Name)

	s := bufio.NewScanner(file)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		parts := strings.SplitN(line, "=", 2)
		if len(parts) < 2 {
			continue
		}
		attribute, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch attribute {
		case "groupId":
			p.GroupID = value
		case "artifactId":
			p.ArtifactID = value
		case "version":
			p.Version = value
		}
	}
	if s.Err() != nil {
		return p, fmt.Errorf("error while scanning zip file %q for pom properties: %w", f.Name, s.Err())
	}
	log.Debugf("Data from pom.properties: groupid: %s artifactid: %s version: %s", p.GroupID, p.ArtifactID, p.Version)
	return p, nil
}
