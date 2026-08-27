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

package spdx

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	convspdx "github.com/google/osv-scalibr/converter/spdx"
)

type writeFun3 func(doc *convspdx.Document3, w io.Writer) error

// Writer functions associated with SPDX v3.0 extensions. SPDX 3.0 only defines a JSON-LD
// serialization, so there is no tag-value or RDF equivalent here.
var spdx3Writers = map[string]writeFun3{
	"spdx3-json": writeSPDX3JSON,
}

// Write3 writes an SPDX v3.0 document into a file in the JSON-LD format.
func Write3(doc *convspdx.Document3, path string, format string) error {
	writeFun, ok := spdx3Writers[format]
	if !ok {
		return fmt.Errorf("%s has an invalid SPDX format or not supported by SCALIBR", path)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return writeFun(doc, f)
}

func writeSPDX3JSON(doc *convspdx.Document3, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
