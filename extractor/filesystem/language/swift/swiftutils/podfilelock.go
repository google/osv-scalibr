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

// Package swiftutils provides utilities for parsing Swift podfiles.
package swiftutils

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// PodfileLock represents the structure of a Podfile.lock file.
type podfileLock struct {
	Pods []any `yaml:"PODS"`
}

// Package represents a single package parsed from Podfile.lock.
type Package struct {
	Name    string
	Version string
}

// ParsePodfileLock parses the contents of a Podfile.lock and returns a list of packages.
func ParsePodfileLock(reader io.Reader) ([]Package, error) {
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to read file: %w", err)
	}

	// Check if the file is empty
	if len(bytes) == 0 {
		return nil, errors.New("file is empty")
	}

	var podfile podfileLock
	if err = yaml.Unmarshal(bytes, &podfile); err != nil {
		return nil, fmt.Errorf("unable to parse YAML: %w", err)
	}

	var pkgs []Package
	for _, podInterface := range podfile.Pods {
		var podBlob string
		switch v := podInterface.(type) {
		case map[string]any:
			for k := range v {
				podBlob = k
			}
		case string:
			podBlob = v
		default:
			return nil, errors.New("malformed Podfile.lock")
		}

		splits := strings.Split(podBlob, " ")
		if len(splits) < 2 {
			return nil, fmt.Errorf("unexpected format in Pods: %s", podBlob)
		}
		podName := splits[0]
		podVersion := strings.TrimSuffix(strings.TrimPrefix(splits[1], "("), ")")
		pkgs = append(pkgs, Package{
			Name:    podName,
			Version: podVersion,
		})
	}

	return pkgs, nil
}
