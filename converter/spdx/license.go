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

package spdx

import (
	"fmt"
	"strings"

	"bitbucket.org/creachadair/stringset"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/thoas/go-funk"
)

const (
	// See https://docs.deps.dev/faq/#how-are-licenses-determined for more license info.

	// NonStandardLicense refers to a non-spdx-compliant license.
	NonStandardLicense = "non-standard"

	// UnknownLicense refers to a license we can't identify.
	UnknownLicense = "unknown"

	// LicenseRefPrefix is the prefix for non-standard licenses.
	LicenseRefPrefix = "LicenseRef-"
)

// LicenseExpression takes an array of licenses and transforms it into an SPDX-compliant license
// expression. These licenses can have come from anywhere, so we don't assume anything about their
// values.
// We parse licenses that are singular expressions (e.g. "MIT") and those that are basic expressions
// (e.g. "MIT AND LGPL").
func LicenseExpression(licenses []string) (string, stringset.Set) {
	cleanLicenses := cleanLicenseExpression(licenses)
	if len(cleanLicenses) == 0 {
		return NoAssertion, stringset.Set{}
	}
	licenseExpressionSet := stringset.New()
	customLicenses := stringset.New()
	for _, l := range cleanLicenses {
		// If there is a nonstandard placeholder value, then we just mark the whole block as
		// NOASSERTION, as we can't construct a license expression with it.
		if strings.EqualFold(l, UnknownLicense) || strings.EqualFold(l, NonStandardLicense) {
			return NoAssertion, stringset.Set{}
		}
		// If we have an OR, then we need to both validate every license inside the expression, and
		// wrap in parentheses, so that it's clear that it's distinct from any ANDs.
		l := strings.ReplaceAll(l, " or ", " OR ")
		if strings.Contains(l, " OR ") {
			orLicenses := []string{}
			orLicenseSplit := strings.Split(l, " OR ")
			for _, ols := range orLicenseSplit {
				spdxL, customL := spdxAndCustomLicenses(ols)
				orLicenses = append(orLicenses, spdxL)
				if customL != "" {
					customLicenses.Add(customL)
				}
			}
			// Combine them back
			licenseExpressionSet.Add(fmt.Sprintf("(%s)", strings.Join(orLicenses, " OR ")))
		} else {
			spdxL, customL := spdxAndCustomLicenses(l)
			licenseExpressionSet.Add(spdxL)
			if customL != "" {
				customLicenses.Add(customL)
			}
		}
	}
	return strings.Join(licenseExpressionSet.Elements(), " AND "), customLicenses
}

// cleanLicenseExpression preparses the licenses to allow extraction, by
// 1. Removing empty licenses
// 2. Stripping off leading/trailing parentheses
// 3. Treating AND licenses as separate licenses
func cleanLicenseExpression(licenses []string) []string {
	cleanLicenses := []string{}
	for _, l := range licenses {
		if l == "" {
			continue
		}
		var noParenLicense string
		if strings.HasPrefix(l, "(") && strings.HasSuffix(l, ")") {
			noParenLicense = l[1 : len(l)-1]
		} else {
			noParenLicense = l
		}
		l = strings.ReplaceAll(noParenLicense, " and ", " AND ")
		cleanLicenses = append(cleanLicenses, strings.Split(l, " AND ")...)
	}
	return cleanLicenses
}

// spdxAndCustomLicenses takes a single license, and returns just it (if it is a valid spdx license)
// or the cleaned version of it for the reference, and the actual text
func spdxAndCustomLicenses(l string) (string, string) {
	_, ok := canonicalLicenses[l]
	if ok {
		return l, ""
	}
	return spdxLicenceRef(l), l
}

// ToOtherLicenses converts a stringset to an SPDX OtherLicense field.
func ToOtherLicenses(otherLicenses stringset.Set) []*v2_3.OtherLicense {
	if otherLicenses.Empty() {
		return nil
	}
	return funk.Map(otherLicenses.Elements(), func(l string) *v2_3.OtherLicense {
		return &v2_3.OtherLicense{LicenseIdentifier: spdxLicenceRef(l), ExtractedText: l}
	}).([]*v2_3.OtherLicense)
}

func spdxLicenceRef(l string) string {
	return LicenseRefPrefix + replaceSPDXIDInvalidChars(l)
}
