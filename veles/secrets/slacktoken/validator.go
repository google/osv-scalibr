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

package slacktoken

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// slackResponse represents the common response structure from Slack API
type slackResponse struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error"`
}

const (
	// slackAPIBaseURL is the base URL for Slack API.
	slackAPIBaseURL = "https://slack.com"
	// SlackAPIEndpoint is the API endpoint for token validation.
	SlackAPIEndpoint = "/api/auth.test"
	// validationTimeout is timeout for API validation requests.
	validationTimeout = 10 * time.Second
)

var (
	// ErrAPIQueryFailed is returned when there is an error while querying the slack APIs during validation.
	ErrAPIQueryFailed = errors.New("error while querying Slack API")
)

func statusFromResponseBody(body io.Reader) (veles.ValidationStatus, error) {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("%w: %v", ErrAPIQueryFailed, err)
	}

	var response slackResponse
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return veles.ValidationFailed, fmt.Errorf("%w: %v", ErrAPIQueryFailed, err)
	}

	if response.Ok {
		return veles.ValidationValid, nil
	}
	if response.Error == "invalid_auth" {
		return veles.ValidationInvalid, nil
	}
	return veles.ValidationFailed, fmt.Errorf("%w: %v", ErrAPIQueryFailed, response.Error)
}

// NewAppLevelTokenValidator creates a new Validator for SlackAppLevelToken.
func NewAppLevelTokenValidator() *simplevalidate.Validator[SlackAppLevelToken] {
	return &simplevalidate.Validator[SlackAppLevelToken]{
		Endpoint:   slackAPIBaseURL + SlackAPIEndpoint,
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(k SlackAppLevelToken) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + k.Token,
				"Content-Type":  "application/x-www-form-urlencoded",
			}
		},
		StatusFromResponseBody: statusFromResponseBody,
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}
}

// NewAppConfigAccessTokenValidator creates a new Validator for SlackAppConfigAccessToken.
func NewAppConfigAccessTokenValidator() *simplevalidate.Validator[SlackAppConfigAccessToken] {
	return &simplevalidate.Validator[SlackAppConfigAccessToken]{
		Endpoint:   slackAPIBaseURL + SlackAPIEndpoint,
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(k SlackAppConfigAccessToken) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + k.Token,
				"Content-Type":  "application/x-www-form-urlencoded",
			}
		},
		StatusFromResponseBody: statusFromResponseBody,
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}
}

// NewAppConfigRefreshTokenValidator creates a new Validator for SlackAppConfigRefreshToken.
func NewAppConfigRefreshTokenValidator() *simplevalidate.Validator[SlackAppConfigRefreshToken] {
	return &simplevalidate.Validator[SlackAppConfigRefreshToken]{
		Endpoint:   slackAPIBaseURL + SlackAPIEndpoint,
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(k SlackAppConfigRefreshToken) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + k.Token,
				"Content-Type":  "application/x-www-form-urlencoded",
			}
		},
		StatusFromResponseBody: statusFromResponseBody,
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}
}
