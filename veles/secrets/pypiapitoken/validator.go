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

package pypiapitoken

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	pypiUploadURL     = "https://upload.pypi.org/legacy/"
	validationTimeout = 10 * time.Second
)

func mustCreateBodyAndContentType() (string, string) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	if err := writer.WriteField(":action", "file_upload"); err != nil {
		panic(err)
	}
	if err := writer.WriteField("name", "dummy-package"); err != nil {
		panic(err)
	}
	if err := writer.WriteField("version", "0.0.1"); err != nil {
		panic(err)
	}
	if err := writer.WriteField("content", "dummy-content"); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}

	return body.String(), writer.FormDataContentType()
}

// NewValidator creates a new Validator that validates PyPI API Tokens by
// attempting to upload a dummy package to PyPI.
// It performs a POST request to the PyPI legacy upload URL with multipart form data
// using the API token in the Authorization header. If the request returns
// HTTP 400 Bad Request, the key is considered valid.
// If HTTP 403 Forbidden, the key is considered invalid.
// Other errors return ValidationFailed.
// We send an invalid package to not add any new package to the account.
func NewValidator() *simplevalidate.Validator[PyPIAPIToken] {
	body, contentType := mustCreateBodyAndContentType()
	return &simplevalidate.Validator[PyPIAPIToken]{
		Endpoint:   pypiUploadURL,
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(k PyPIAPIToken) map[string]string {
			return map[string]string{
				"Authorization": "token " + k.Token,
				"Content-Type":  contentType,
			}
		},
		Body: func(_ PyPIAPIToken) string {
			return body
		},
		ValidResponseCodes:   []int{http.StatusBadRequest},
		InvalidResponseCodes: []int{http.StatusForbidden},
		HTTPC: &http.Client{
			Timeout: validationTimeout,
		},
	}
}
