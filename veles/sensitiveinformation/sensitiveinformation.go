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

// Package sensitiveinformation provides types for representing sensitive
// information found by Veles detectors.
// All Veles sensitive information detectors should emit SensitiveInformation
// from this package. No validation will be performed on sensitive information.
package sensitiveinformation

// SensitivityLevel represents the sensitivity of an infoType.
type SensitivityLevel int

const (
	// SensitivityLevelUnspecified is the default value.
	SensitivityLevelUnspecified SensitivityLevel = iota
	// SensitivityLevelLow is the lowest sensitivity level.
	SensitivityLevelLow
	// SensitivityLevelModerate is the moderate sensitivity level.
	SensitivityLevelModerate
	// SensitivityLevelHigh is the highest sensitivity level.
	SensitivityLevelHigh
)

// Likelihood represents the confidence level that a piece of data matches an infoType.
type Likelihood int

const (
	// LikelihoodUnspecified is the default value.
	LikelihoodUnspecified Likelihood = iota
	// LikelihoodUnlikely represents a high chance of a false positive.
	LikelihoodUnlikely
	// LikelihoodLikely represents a low chance of a false positive.
	LikelihoodLikely
	// LikelihoodVeryLikely represents a very low chance of a false positive.
	LikelihoodVeryLikely
)

// InfoType is the type of sensitive information found.
type InfoType struct {
	// Name is the name of the info type (e.g. "PASSPORT_NUMBER").
	Name string
	// Sensitivity is the level of sensitivity of the info type.
	Sensitivity SensitivityLevel
}

// SensitiveInformation is a piece of sensitive information found by a Veles
// detector.
type SensitiveInformation struct {
	// InfoType is the type of sensitive information found.
	InfoType InfoType
	// Likelihood is the level of confidence that the found data is a certain
	// type of sensitive information.
	Likelihood Likelihood
	// Raw is the raw data found by the detector.
	Raw []byte
}
