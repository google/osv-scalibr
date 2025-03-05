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

// Package severity implements severity calculation for OSV records.
package severity

import (
	"fmt"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

// CalculateScore returns the numeric score for the given severity field.
// i.e. returns the CVSS Score (0.0 - 10.0)
//
// returns (-1.0, nil) if the severity is the empty struct.
// returns (-1.0, error) if severity type or score is invalid.
func CalculateScore(severity osvschema.Severity) (float64, error) {
	var empty osvschema.Severity
	if severity == empty {
		return -1.0, nil
	}

	switch severity.Type {
	case osvschema.SeverityCVSSV2:
		vec, err := gocvss20.ParseVector(severity.Score)
		if err != nil {
			return -1.0, err
		}
		return vec.BaseScore(), nil
	case osvschema.SeverityCVSSV3:
		switch {
		case strings.HasPrefix(severity.Score, "CVSS:3.0/"):
			vec, err := gocvss30.ParseVector(severity.Score)
			if err != nil {
				return -1.0, err
			}
			return vec.BaseScore(), nil
		case strings.HasPrefix(severity.Score, "CVSS:3.1/"):
			vec, err := gocvss31.ParseVector(severity.Score)
			if err != nil {
				return -1.0, err
			}
			return vec.BaseScore(), nil
		default:
			return -1.0, fmt.Errorf("unsupported CVSS_V3 version: %s", severity.Score)
		}
	case osvschema.SeverityCVSSV4:
		vec, err := gocvss40.ParseVector(severity.Score)
		if err != nil {
			return -1.0, err
		}
		return vec.Score(), nil

	default:
		return -1.0, fmt.Errorf("unsupported severity type: %s", severity.Type)
	}
}
