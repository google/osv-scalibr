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

package salesforceoauth2jwt_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/salesforceoauth2jwt"
)

const (
	testClientID      = "3MVG123456789.AB_CDEF.ABC123456789ABC123456789ABC1"
	testUsername      = "test@example.com"
	testPrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDDwxXFmUGrIkQZ
AJ1yFkkXrOOCH3RL4QsGk24xTj7iO/ozauKXoVys3wKAzK9iwlfBY36kqqn0hvL9
YhrnHAGfQJTGMnwkbZvWV6u6IKWxKqPGQp4ULIbveYd6FoXPMcwULdoRQeR+kez8
aPzyu/L4cnlk31J6WqpNnjohmndAkaRnx/mGRYcn+xDvOcJbmLSHQHYgCigHzENg
uilu4N9KLsD6+N0c1prr79STsiR9HRozkS+ySpiS1tG9jYMAlKSp3L+hgQDqvcK5
j5zyJx7iDmIdmQjmbpnLaxj8cjW+c5FzEoqZ2pXCuLDMTOfGnzFxrRzf5Mc8tw+9
hPRrkv+fAgMBAAECggEAGn6+5Z2We7kJinDA3n4Rqnil2iizrslomp09nsK+VBRW
Crt+q5MVXfhY+GG7oxw2kGAM9fB7TDMvlAfBKGJr/cfZ2vFeR/flzZ7UCT797fqd
a+n8RzK3mJXUNjvyJFbTDjAegZNvf4n0jz0ObzPs8J9dur9XBGRdBGBT8dRcK4rN
+F9qh8JYwM+cXYbDjKvoLoxTSeCxREJ2KHVueCGxTBAwkmUXiF0jnxueqLoThoAT
TLzyTYw+20F4vRJMVpLZO6X7GOht1NkIbi4vFTKh8iAnUGXRUZ8W+evW2NykGd0q
0QsDsFO/Oc8Xn2DZTCutGUsHeDxq4XApnNk04t13sQKBgQDw+79+6E9xXjYUwZrG
TyMb1j1va/oGEVaxPgSGm5RHcjW4xesdCftOT3eckFNVWzk4V7sG9as/s0FMQ0M3
TchY8FkeK/iOBbZDExmmeDPvxzexC7nRCB+NOJZML9zCN8PTkje96uXWjTCCbJTu
zqnliDLTBsXJQt1XJXU5ZnIQxQKBgQDP9fNEyRzNXttKL7lj9zutDe5AMHS10hoR
gMBnRKlte3VKZfRauna/Lv3afhFHwZAEWnkUhQUK9lE8U9EnIoPNPW7jAaO69BHo
1/gXR9rZibiTnYczCS9XlXaER3139Mjjn3W0v12Vi9Fylqgx2oyb1HaDtRr6HNun
P33B8dbNEwKBgQDoOnLMJauJILUVQ42X1eOLi+YgXfnPpx3YKF/MKFm4kENdEL4G
efwH92TZJ+xmsUZvGXxOtKiW9nPSvm8j+H092EDJZq5cjvyZnup1FhlW1LDCmP40
hpOBUCrmuKkRMRQx6xJ0ns1m+SDqTyEnEVmArMPtwPURgrIyrRJOgn8h0QKBgAK4
K6M1ogvJdsKklx8Ih54+tWPfflc2VSLvdRSkoDaPS7xaUvSwxYbAfY9S4LT4ggKc
kELFbohzKiLI0c5aNDEF4aJUTijOskFCObtMND9t/pznjXIMZ7MUgEVAjhJ4f/wC
BM8FRZsEBgwijjaAriAHijk0sBKfN/wa53EW0YFDAoGAE+k5Eq/L+/G4pDcOwm55
kEzYclnfD38ZM9DfPB6k0K55TubLL9PeltRkR5yy4tjlBlDPx6wzMhbd0Xq3iCzq
Twanj5YBWrq2yV2fqWgvyz3LIqlhmDNW89ThWmk7XYtD0em9dnEXlpH0JTxdQpCF
tGOp/d/V3F66yalNSTXNbkA=
-----END PRIVATE KEY-----`
)

// mockTransport redirects login.salesforce.com to mock server
type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "login.salesforce.com" {
		testURL, _ := url.Parse(m.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// mockSalesforceServer validates grant_type and that assertion exists
func mockSalesforceServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/services/oauth2/token" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm failed: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("missing or wrong grant_type")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if assertion := r.Form.Get("assertion"); assertion == "" {
			t.Errorf("assertion missing")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.WriteHeader(status)
	}))
}

func TestValidator_ValidJWT(t *testing.T) {
	server := mockSalesforceServer(t, http.StatusOK)
	defer server.Close()

	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := salesforceoauth2jwt.NewValidator()
	validator.HTTPC = client

	creds := salesforceoauth2jwt.Credentials{
		ID:         testClientID,
		Username:   testUsername,
		PrivateKey: testPrivateKeyPEM,
	}

	got, err := validator.Validate(context.Background(), creds)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if got != veles.ValidationValid {
		t.Errorf("expected Valid, got %v", got)
	}
}

func TestValidator_InvalidUser(t *testing.T) {
	server := mockSalesforceServer(t, http.StatusUnauthorized)
	defer server.Close()

	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := salesforceoauth2jwt.NewValidator()
	validator.HTTPC = client

	creds := salesforceoauth2jwt.Credentials{
		ID:         testClientID,
		Username:   "invalid@example.com",
		PrivateKey: testPrivateKeyPEM,
	}

	got, err := validator.Validate(context.Background(), creds)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if got != veles.ValidationInvalid {
		t.Errorf("expected Invalid, got %v", got)
	}
}

func TestValidator_MalformedPrivateKey(t *testing.T) {
	validator := salesforceoauth2jwt.NewValidator()

	creds := salesforceoauth2jwt.Credentials{
		ID:         testClientID,
		Username:   testUsername,
		PrivateKey: "NOT A KEY",
	}

	got, err := validator.Validate(context.Background(), creds)

	if err == nil {
		t.Errorf("expected error for malformed private key, got nil")
	}
	if got != veles.ValidationInvalid {
		t.Errorf("expected Invalid due to malformed key, got %v", got)
	}
}

func TestValidator_ContextCancelled(t *testing.T) {
	server := mockSalesforceServer(t, http.StatusOK)
	defer server.Close()

	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := salesforceoauth2jwt.NewValidator()
	validator.HTTPC = client

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	creds := salesforceoauth2jwt.Credentials{
		ID:         testClientID,
		Username:   testUsername,
		PrivateKey: testPrivateKeyPEM,
	}

	got, err := validator.Validate(ctx, creds)

	if err == nil {
		t.Errorf("expected context cancellation error, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("expected Failed due to cancelled context, got %v", got)
	}
}

func TestValidator_ServerError(t *testing.T) {
	server := mockSalesforceServer(t, http.StatusInternalServerError)
	defer server.Close()

	client := &http.Client{
		Transport: &mockTransport{testServer: server},
	}

	validator := salesforceoauth2jwt.NewValidator()
	validator.HTTPC = client

	creds := salesforceoauth2jwt.Credentials{
		ID:         testClientID,
		Username:   testUsername,
		PrivateKey: testPrivateKeyPEM,
	}

	got, err := validator.Validate(context.Background(), creds)

	if err == nil {
		t.Errorf("expected error for 500, got nil")
	}
	if got != veles.ValidationFailed {
		t.Errorf("expected Failed for server error, got %v", got)
	}
}
