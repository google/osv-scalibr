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

package sap

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

const (
	// maxURLLength is the maximum length of a valid SAP URL.
	// URLs are dynamic entities so there's no fixed length.
	// Articles from websites and real world demonstrations from youtube videos suggest that it's approaching 150.
	// Therefore, 150 is a good upper bound.
	// For reference:
	// http://developer.ibm.com/developer/default/tutorials/integrate-sap-business-technology-platform-audit-logs-with-ibm-security-qradar/images/figure2.png
	// https://help.figaf.com/portal/en/kb/articles/create-service-keys-for-sap-cpi-cloud-foundry#To_create_a_service_key_for_running_test_follow_the_procedure1__Goto_SAP_BTP_Cockpit_and_open_subaccount_for_your_development2_Click_Instances_and_Subscription3_Create4_Fill_in_the_following_information_Plan_should_be_integration_flow_and_the_space_your_current_space5_On_the_roles_page_select_the_roles_AuthGroup_AdministratorAuthGroup_BusinessExpertAuthGroup_IntegrationDeveloperAccessAllAccessPoliciesArtifacts6_Select_next_and_create7_Once_it_is_created_select_the_item_and_in_the_details_select_Create_Service_Key8_Give_it_a_name_and_select_create9_Once_it_is_created_you_can_view_the_JSON_data_use_this_when_you_are_creating_the_account
	// https://www.youtube.com/watch?t=416&si=G51ZmarBpVx4wiCZ&v=LAUNofd2v-k&feature=youtu.be
	maxURLLength = 150

	// JWT payload claim keys used to identify SAP tokens.
	payloadIssuerKey   = "iss"
	payloadClientIDKey = "cid"

	maxAccessTokenLength = 8210
	maxJWTLength         = 8192
)

var (
	accessTokenRe = regexp.MustCompile(`(?i)\baccess[_-]?token\b\s*[:=]?\s*(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b`)
	// urlRe is a regular expression that matches SAP BTP URL.
	// For reference:
	// http://developer.ibm.com/developer/default/tutorials/integrate-sap-business-technology-platform-audit-logs-with-ibm-security-qradar/images/figure2.png
	// https://help.figaf.com/portal/en/kb/articles/create-service-keys-for-sap-cpi-cloud-foundry#To_create_a_service_key_for_running_test_follow_the_procedure1__Goto_SAP_BTP_Cockpit_and_open_subaccount_for_your_development2_Click_Instances_and_Subscription3_Create4_Fill_in_the_following_information_Plan_should_be_integration_flow_and_the_space_your_current_space5_On_the_roles_page_select_the_roles_AuthGroup_AdministratorAuthGroup_BusinessExpertAuthGroup_IntegrationDeveloperAccessAllAccessPoliciesArtifacts6_Select_next_and_create7_Once_it_is_created_select_the_item_and_in_the_details_select_Create_Service_Key8_Give_it_a_name_and_select_create9_Once_it_is_created_you_can_view_the_JSON_data_use_this_when_you_are_creating_the_account
	// https://www.youtube.com/watch?t=416&si=G51ZmarBpVx4wiCZ&v=LAUNofd2v-k&feature=youtu.be
	urlRe = regexp.MustCompile(`(?i)\burl\b\s*[:=]?\s*([a-zA-Z0-9.-]+\.cfapps\.[a-zA-Z0-9-]+\.hana\.ondemand\.com)\b`)
)

// NewBTPAccessTokenDetector returns a detector that matches SAP BTP Credentials.
func NewBTPAccessTokenDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxAccessTokenLength, maxURLLength),
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			findValidSAPBTPTokens(clientIDRe),
			ntuple.FindAllMatchesGroup(urlRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return AccessToken{Token: string(ms[0].Value), URL: string(ms[1].Value)}, true
		},
	}
}

// NewBTPXSUAAAccessTokenDetector returns a detector that matches SAP BTP XSUAA Credentials.
func NewBTPXSUAAAccessTokenDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxAccessTokenLength, maxURLLength),
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			findValidSAPBTPTokens(xsuaaClientIDRe),
			ntuple.FindAllMatchesGroup(urlRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return AccessToken{Token: string(ms[0].Value), URL: string(ms[1].Value)}, true
		},
	}
}

func findValidSAPBTPTokens(clientIDRe *regexp.Regexp) ntuple.Finder {
	return func(data []byte) []ntuple.Match {
		matches := accessTokenRe.FindAllSubmatchIndex(data, -1)
		results := make([]ntuple.Match, 0, len(matches))

		for _, idx := range matches {
			// idx layout:
			// [fullStart, fullEnd, g1Start, g1End]

			if len(idx) < 4 || idx[2] < 0 || idx[3] < 0 {
				continue
			}

			fullStart := idx[0]
			fullEnd := idx[1]
			jwtBytes := data[idx[2]:idx[3]]

			if len(jwtBytes) > maxJWTLength {
				continue
			}

			payload, ok := parseJWTPayload(jwtBytes)
			if !ok {
				continue
			}

			iss, ok := payload[payloadIssuerKey].(string)
			if !ok || !isValidSAPBTPIssuer(iss) {
				continue
			}

			cid, ok := payload[payloadClientIDKey].(string)
			if !ok || !clientIDRe.MatchString(cid) {
				continue
			}

			results = append(results, ntuple.Match{
				Start: fullStart,
				End:   fullEnd,
				Value: jwtBytes,
			})
		}

		return results
	}
}

func parseJWTPayload(token []byte) (map[string]any, bool) {
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 {
		return nil, false
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, false
	}

	return payload, true
}

// isValidSAPIssuer checks if issuer contains SAP products arifacts
func isValidSAPBTPIssuer(iss string) bool {
	return strings.Contains(iss, "hana") || strings.Contains(iss, "concur")
}
