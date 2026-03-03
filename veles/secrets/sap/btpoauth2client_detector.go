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
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

const (
	// maxIDLength is the maximum length of a valid client ID.
	// There is not documented length.
	// Articles from websites and real world demonstrations from youtube videos suggest that it's between 50 and 80.
	// Reference:
	// https://help.figaf.com/portal/en/kb/articles/create-service-keys-for-sap-cpi-cloud-foundry#To_create_a_service_key_for_running_test_follow_the_procedure1__Goto_SAP_BTP_Cockpit_and_open_subaccount_for_your_development2_Click_Instances_and_Subscription3_Create4_Fill_in_the_following_information_Plan_should_be_integration_flow_and_the_space_your_current_space5_On_the_roles_page_select_the_roles_AuthGroup_AdministratorAuthGroup_BusinessExpertAuthGroup_IntegrationDeveloperAccessAllAccessPoliciesArtifacts6_Select_next_and_create7_Once_it_is_created_select_the_item_and_in_the_details_select_Create_Service_Key8_Give_it_a_name_and_select_create9_Once_it_is_created_you_can_view_the_JSON_data_use_this_when_you_are_creating_the_account
	// https://www.youtube.com/watch?t=416&si=G51ZmarBpVx4wiCZ&v=LAUNofd2v-k&feature=youtu.be
	maxIDLength = 80

	// maxSecretLength is the maximum length of a valid client secret.
	// There is not documented length.
	// An article from a website and a real demonstration from a youtube video suggests that it's around 150.
	// For reference:
	// https://help.figaf.com/portal/en/kb/articles/create-service-keys-for-sap-cpi-cloud-foundry#To_create_a_service_key_for_running_test_follow_the_procedure1__Goto_SAP_BTP_Cockpit_and_open_subaccount_for_your_development2_Click_Instances_and_Subscription3_Create4_Fill_in_the_following_information_Plan_should_be_integration_flow_and_the_space_your_current_space5_On_the_roles_page_select_the_roles_AuthGroup_AdministratorAuthGroup_BusinessExpertAuthGroup_IntegrationDeveloperAccessAllAccessPoliciesArtifacts6_Select_next_and_create7_Once_it_is_created_select_the_item_and_in_the_details_select_Create_Service_Key8_Give_it_a_name_and_select_create9_Once_it_is_created_you_can_view_the_JSON_data_use_this_when_you_are_creating_the_account
	// https://www.youtube.com/watch?t=416&si=G51ZmarBpVx4wiCZ&v=LAUNofd2v-k&feature=youtu.be
	maxSecretLength = 250

	// maxURLLength is the maximum length of a valid SAP Token URL.
	// URLs are dynamic entities so there's no fixed length.
	// Articles from websites and real world demonstrations from youtube videos suggest that it's approaching 100.
	// Therefore, 100 is a good upper bound.
	// For reference:
	// https://help.figaf.com/portal/en/kb/articles/create-service-keys-for-sap-cpi-cloud-foundry#To_create_a_service_key_for_running_test_follow_the_procedure1__Goto_SAP_BTP_Cockpit_and_open_subaccount_for_your_development2_Click_Instances_and_Subscription3_Create4_Fill_in_the_following_information_Plan_should_be_integration_flow_and_the_space_your_current_space5_On_the_roles_page_select_the_roles_AuthGroup_AdministratorAuthGroup_BusinessExpertAuthGroup_IntegrationDeveloperAccessAllAccessPoliciesArtifacts6_Select_next_and_create7_Once_it_is_created_select_the_item_and_in_the_details_select_Create_Service_Key8_Give_it_a_name_and_select_create9_Once_it_is_created_you_can_view_the_JSON_data_use_this_when_you_are_creating_the_account
	// https://www.youtube.com/watch?t=416&si=G51ZmarBpVx4wiCZ&v=LAUNofd2v-k&feature=youtu.be
	maxTokenURLLength = 100

	// maxDistance is the maximum distance between Service Principal Client IDs, Secrects, URLs, and TokenURLs to be considered for pairing.
	// 10 KiB is a good upper bound as we don't expect files containing credentials to be larger than this.
	maxDistance = 10 * 1 << 10 // 10 KiB
)

var (
	// clientIDRe is a regular expression that matches SAP OAuth2 Client IDs.
	// Client ID starts with a "sb-" prefix, immediately followed by an UUID, and additional strings separated by "!".
	// References:
	// https://help.figaf.com/portal/en/kb/articles/create-service-keys-for-sap-cpi-cloud-foundry#To_create_a_service_key_for_running_test_follow_the_procedure1__Goto_SAP_BTP_Cockpit_and_open_subaccount_for_your_development2_Click_Instances_and_Subscription3_Create4_Fill_in_the_following_information_Plan_should_be_integration_flow_and_the_space_your_current_space5_On_the_roles_page_select_the_roles_AuthGroup_AdministratorAuthGroup_BusinessExpertAuthGroup_IntegrationDeveloperAccessAllAccessPoliciesArtifacts6_Select_next_and_create7_Once_it_is_created_select_the_item_and_in_the_details_select_Create_Service_Key8_Give_it_a_name_and_select_create9_Once_it_is_created_you_can_view_the_JSON_data_use_this_when_you_are_creating_the_account
	// https://www.youtube.com/watch?t=416&si=G51ZmarBpVx4wiCZ&v=LAUNofd2v-k&feature=youtu.be// SAP client ID format:
	// sb-<UUID 32-36 chars>!<segment1>|<segment2>!<segment3>
	clientIDRe = regexp.MustCompile(`\bsb-[a-zA-Z0-9-]{32,36}![a-zA-Z0-9-]+\|[a-zA-Z0-9-]+![a-zA-Z0-9-]+`)

	// xsuaaClientIDRe is a regular expression that matches SAP BTP XSUAA OAuth2 Client IDs.
	// SAP BTP XSUAA Client ID format:
	// sb-<xsappname>!<index>
	xsuaaClientIDRe = regexp.MustCompile(`\bsb-[a-zA-Z0-9-]+![a-zA-Z0-9-]+`)

	// clientSecretRe is a regular expression that matches SAP OAuth2 Client Secrets.
	// Articles from websites and real world demonstrations from youtube videos suggest that it's an UUID-like string.
	// In the format: UUID + $ + base64 20+
	// References:
	// https://help.figaf.com/portal/en/kb/articles/create-service-keys-for-sap-cpi-cloud-foundry#To_create_a_service_key_for_running_test_follow_the_procedure1__Goto_SAP_BTP_Cockpit_and_open_subaccount_for_your_development2_Click_Instances_and_Subscription3_Create4_Fill_in_the_following_information_Plan_should_be_integration_flow_and_the_space_your_current_space5_On_the_roles_page_select_the_roles_AuthGroup_AdministratorAuthGroup_BusinessExpertAuthGroup_IntegrationDeveloperAccessAllAccessPoliciesArtifacts6_Select_next_and_create7_Once_it_is_created_select_the_item_and_in_the_details_select_Create_Service_Key8_Give_it_a_name_and_select_create9_Once_it_is_created_you_can_view_the_JSON_data_use_this_when_you_are_creating_the_account
	// https://www.youtube.com/watch?t=416&si=G51ZmarBpVx4wiCZ&v=LAUNofd2v-k&feature=youtu.be
	clientSecretRe = regexp.MustCompile(`(?i)\bclient[_-]?secret\b\s*[:=]?\s*([a-zA-Z0-9-]{32,36}\$[a-zA-Z0-9-=]{20,})`)

	// tokenURLRe is a regular expression that matches SAP Token URL.
	// References:
	// https://help.figaf.com/portal/en/kb/articles/create-service-keys-for-sap-cpi-cloud-foundry#To_create_a_service_key_for_running_test_follow_the_procedure1__Goto_SAP_BTP_Cockpit_and_open_subaccount_for_your_development2_Click_Instances_and_Subscription3_Create4_Fill_in_the_following_information_Plan_should_be_integration_flow_and_the_space_your_current_space5_On_the_roles_page_select_the_roles_AuthGroup_AdministratorAuthGroup_BusinessExpertAuthGroup_IntegrationDeveloperAccessAllAccessPoliciesArtifacts6_Select_next_and_create7_Once_it_is_created_select_the_item_and_in_the_details_select_Create_Service_Key8_Give_it_a_name_and_select_create9_Once_it_is_created_you_can_view_the_JSON_data_use_this_when_you_are_creating_the_account
	// https://www.youtube.com/watch?t=416&si=G51ZmarBpVx4wiCZ&v=LAUNofd2v-k&feature=youtu.be
	tokenURLRe = regexp.MustCompile(`\b[a-zA-Z0-9.-]+\.authentication\.[a-zA-Z0-9]+\.hana\.ondemand\.com(?:\/oauth\/token)?\b`)
)

// NewBTPOAuth2ClientCredentialsDetector returns a detector that matches SAP BTP or S/4HANA OAuth2 Client Credentials.
func NewBTPOAuth2ClientCredentialsDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxIDLength, maxSecretLength, maxTokenURLLength, maxURLLength),
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatches(clientIDRe),
			ntuple.FindAllMatchesGroup(clientSecretRe),
			ntuple.FindAllMatches(tokenURLRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return BTPOAuth2ClientCredentials{ID: string(ms[0].Value), Secret: string(ms[1].Value), TokenURL: string(ms[2].Value)}, true
		},
	}
}

// NewBTPXSUAAOAuth2ClientCredentialsDetector returns a detector that matches SAP BTP or S/4HANA XSUAA OAuth2 Client Credentials.
func NewBTPXSUAAOAuth2ClientCredentialsDetector() veles.Detector {
	return &ntuple.Detector{
		MaxElementLen: max(maxIDLength, maxSecretLength, maxTokenURLLength, maxURLLength),
		MaxDistance:   maxDistance,
		Finders: []ntuple.Finder{
			ntuple.FindAllMatches(xsuaaClientIDRe),
			ntuple.FindAllMatchesGroup(clientSecretRe),
			ntuple.FindAllMatches(tokenURLRe),
		},
		FromTuple: func(ms []ntuple.Match) (veles.Secret, bool) {
			return BTPOAuth2ClientCredentials{ID: string(ms[0].Value), Secret: string(ms[1].Value), TokenURL: string(ms[2].Value)}, true
		},
	}
}
