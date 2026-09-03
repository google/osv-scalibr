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

package archive

import (
	"fmt"
	"io"

	"deps.dev/util/maven"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/internal/mavenutil"
)

type pomXMLSource interface {
	Open() (io.ReadCloser, error)
}

func parsePomXML(file pomXMLSource) (*maven.Project, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("could not open POM: %w", err)
	}
	defer reader.Close()

	var project *maven.Project
	if err := datasource.NewMavenDecoder(reader).Decode(&project); err != nil {
		return nil, fmt.Errorf("could not parse POM: %w", err)
	}

	project.ProjectKey = mavenutil.ProjectKey(*project)
	if err := project.Interpolate(); err != nil {
		return nil, fmt.Errorf("could not interpolate POM: %w", err)
	}

	project.ProcessDependencies(func(groupID, artifactID, version maven.String) (maven.DependencyManagement, error) {
		// No need to process dependency management. Metadata for concrete versions was already
		// resolved at build time and is present in the other POMs bundled in this JAR.
		return maven.DependencyManagement{}, nil
	})

	return project, nil
}
