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

// Package spdx provides utilities for writing SPDX documents to the filesystem.
package spdx

import (
	"fmt"
	"io"
	"os"

	"github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/spdx/tools-golang/tagvalue"
	"github.com/spdx/tools-golang/yaml"
)

type writeFun func(doc *v2_3.Document, w io.Writer) error

// Writer functions associated with SPDX v2.3 extensions.
var spdx23Writers = map[string]writeFun{
	"spdx23-tag-value": writeSPDX23TagValue,
	"spdx23-json":      writeSPDX23JSON,
	"spdx23-yaml":      writeSPDX23YAML,
}

// Write23 writes an SPDX v2.3 document into a file in the tag value format.
func Write23(doc *v2_3.Document, path string, format string) error {
	writeFun, ok := spdx23Writers[format]
	if !ok {
		return fmt.Errorf("%s has an invalid SPDX format or not supported by SCALIBR", path)
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = writeFun(doc, f); err != nil {
		return err
	}
	return nil
}

func writeSPDX23TagValue(doc *v2_3.Document, w io.Writer) error {
	return tagvalue.Write(doc, w)
}

func writeSPDX23YAML(doc *v2_3.Document, w io.Writer) error {
	return yaml.Write(doc, w)
}

func writeSPDX23JSON(doc *v2_3.Document, w io.Writer) error {
	return json.Write(doc, w, json.Indent("  "))
}
