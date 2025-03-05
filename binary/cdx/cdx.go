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

// Package cdx provides utilities for writing CycloneDX documents to the filesystem.
package cdx

import (
	"fmt"
	"os"

	"github.com/CycloneDX/cyclonedx-go"
)

// Write writes an CDX document into a file in the chosen format.
func Write(doc *cyclonedx.BOM, path string, format string) error {
	var cdxFormat cyclonedx.BOMFileFormat
	switch format {
	case "cdx-json":
		cdxFormat = cyclonedx.BOMFileFormatJSON
	case "cdx-xml":
		cdxFormat = cyclonedx.BOMFileFormatXML
	default:
		return fmt.Errorf("%s has an invalid CDX format or not supported by SCALIBR", path)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	encoder := cyclonedx.NewBOMEncoder(f, cdxFormat).SetPretty(true)

	return encoder.Encode(doc)
}
