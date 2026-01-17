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

	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

// CalculateScoreAndRating returns the numeric score and rating for the given severity field.
// i.e. returns the CVSS Score (0.0 - 10.0) and the rating (e.g. "CRITICAL")
//
// returns (-1.0, "UNKNOWN", nil) if the severity is the empty struct.
// returns (-1.0, "", error) if severity type or score is invalid.
func CalculateScoreAndRating(severity *osvpb.Severity) (float64, string, error) {
	if severity == nil || severity.Score == "" {
		return -1.0, "UNKNOWN", nil
	}

	switch severity.Type {
	case osvpb.Severity_CVSS_V2:
		vec, err := gocvss20.ParseVector(severity.Score)
		if err != nil {
			return -1.0, "", err
		}
		score := vec.BaseScore()
		// CVSS 2.0 does not have a rating. Use the CVSS 3.0 rating instead.
		rating, err := gocvss30.Rating(score)
		if err != nil {
			rating = "UNKNOWN"
		}
		return score, rating, nil
	case osvpb.Severity_CVSS_V3:
		switch {
		case strings.HasPrefix(severity.Score, "CVSS:3.0/"):
			vec, err := gocvss30.ParseVector(severity.Score)
			if err != nil {
				return -1.0, "", err
			}
			score := vec.BaseScore()
			rating, err := gocvss30.Rating(score)
			if err != nil {
				rating = "UNKNOWN"
			}
			return score, rating, nil
		case strings.HasPrefix(severity.Score, "CVSS:3.1/"):
			vec, err := gocvss31.ParseVector(severity.Score)
			if err != nil {
				return -1.0, "", err
			}
			score := vec.BaseScore()
			rating, err := gocvss31.Rating(score)
			if err != nil {
				rating = "UNKNOWN"
			}
			return score, rating, nil
		default:
			return -1.0, "", fmt.Errorf("unsupported CVSS_V3 version: %s", severity.Score)
		}
	case osvpb.Severity_CVSS_V4:
		vec, err := gocvss40.ParseVector(severity.Score)
		if err != nil {
			return -1.0, "", err
		}
		score := vec.Score()
		rating, err := gocvss40.Rating(score)
		if err != nil {
			rating = "UNKNOWN"
		}
		return score, rating, nil

	default:
		return -1.0, "", fmt.Errorf("unsupported severity type: %s", severity.Type)
	}
}

// CalculateScore returns the numeric score for the given severity field.
// i.e. returns the CVSS Score (0.0 - 10.0)
//
// returns (-1.0, nil) if the severity is the empty struct.
// returns (-1.0, error) if severity type or score is invalid.
func CalculateScore(severity *osvpb.Severity) (float64, error) {
	score, _, err := CalculateScoreAndRating(severity)
	return score, err
}
