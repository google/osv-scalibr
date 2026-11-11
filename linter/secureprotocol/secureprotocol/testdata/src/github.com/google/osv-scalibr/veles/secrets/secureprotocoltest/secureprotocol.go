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

package secureprotocoltest

import (
	"context"
	"net/http"

	"github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const insecureBase = "http://api.example.com"

var _ = &simplevalidate.Validator[string]{
	Endpoint: "https://api.example.com/account",
}

var _ = &simplevalidate.Validator[string]{
	Endpoint: insecureBase + "/account", // want `hardcoded HTTP validator endpoint "http://api.example.com/account" uses scheme "http"; use HTTPS`
}

var _ = &simplevalidate.Validator[string]{
	Endpoints: []string{
		"https://api.example.com/one",
		"http://api.example.com/two", // want `hardcoded HTTP validator endpoint "http://api.example.com/two" uses scheme "http"; use HTTPS`
	},
}

func requests(ctx context.Context, dynamicURL string) {
	_, _ = http.NewRequest(http.MethodGet, "http://api.example.com/account", nil) // want `hardcoded HTTP validator endpoint "http://api.example.com/account" uses scheme "http"; use HTTPS`
	_, _ = http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.com/account", nil)
	_, _ = http.NewRequest(http.MethodGet, dynamicURL, nil)
}
