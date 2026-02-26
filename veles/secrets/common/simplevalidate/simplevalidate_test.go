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

package simplevalidate_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
	"github.com/google/osv-scalibr/veles/velestest"
)

type mockRoundTripper struct {
	want           *http.Request
	respStatusCode int
	respBody       []byte
	err            error
	t              *testing.T
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	opts := []cmp.Option{
		cmpopts.IgnoreUnexported(http.Request{}),
		cmpopts.IgnoreFields(http.Request{}, "Proto", "ProtoMajor", "ProtoMinor", "GetBody"),
	}
	if diff := cmp.Diff(m.want, req, opts...); diff != "" {
		m.t.Fatalf("Received unexpected request (-want +got):\n%s", diff)
	}

	return &http.Response{
		StatusCode: m.respStatusCode,
		Body:       io.NopCloser(bytes.NewReader(m.respBody)),
	}, m.err
}

type multiRoundTripper struct {
	wantRequests []*http.Request
	statusCodes  []int
	respBodies   [][]byte
	callCount    int
	t            *testing.T
}

func (m *multiRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.callCount >= len(m.wantRequests) {
		m.t.Fatalf("unexpected extra request: %v", req.URL)
	}

	opts := []cmp.Option{
		cmpopts.IgnoreUnexported(http.Request{}),
		cmpopts.IgnoreFields(http.Request{}, "Proto", "ProtoMajor", "ProtoMinor", "GetBody", "Header"),
	}

	if diff := cmp.Diff(m.wantRequests[m.callCount], req, opts...); diff != "" {
		m.t.Fatalf("unexpected request (-want +got):\n%s", diff)
	}

	resp := &http.Response{
		StatusCode: m.statusCodes[m.callCount],
		Body:       io.NopCloser(bytes.NewReader(m.respBodies[m.callCount])),
	}

	m.callCount++
	return resp, nil
}

// mustParse is used for creating URLs in a "single-value" context.
// It panics if the URL is invalid.
func mustParse(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic("url.Parse: invalid URL string: " + s)
	}
	return u
}

func TestValidate(t *testing.T) {
	testSecret := "TEST-SECRET"
	testURLStr := "https://test"
	testHost := "test"
	testURL, err := url.Parse(testURLStr)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", testURLStr, err)
	}
	url1 := "https://endpoint1"
	url2 := "https://endpoint2"

	tests := []struct {
		desc      string
		validator *sv.Validator[velestest.FakeStringSecret]
		secret    string
		transport http.RoundTripper
		want      veles.ValidationStatus
		wantErr   error
	}{
		{
			desc: "valid_response",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				Endpoint:   testURLStr,
				HTTPMethod: http.MethodGet,
				HTTPHeaders: func(s velestest.FakeStringSecret) map[string]string {
					return map[string]string{"Authorization": "Bearer " + s.Value}
				},
				ValidResponseCodes: []int{http.StatusOK},
			},
			secret: testSecret,
			transport: &mockRoundTripper{
				want: &http.Request{
					Method: http.MethodGet,
					URL:    testURL,
					Host:   testHost,
					Header: http.Header{"Authorization": []string{"Bearer " + testSecret}},
				},
				respStatusCode: http.StatusOK,
				t:              t,
			},
			want: veles.ValidationValid,
		},
		{
			desc: "invalid_response",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				Endpoint:   testURLStr,
				HTTPMethod: http.MethodGet,
				HTTPHeaders: func(s velestest.FakeStringSecret) map[string]string {
					return map[string]string{"Authorization": "Bearer " + s.Value}
				},
				ValidResponseCodes:   []int{http.StatusOK},
				InvalidResponseCodes: []int{http.StatusUnauthorized},
			},
			secret: testSecret,
			transport: &mockRoundTripper{
				want: &http.Request{
					Method: http.MethodGet,
					URL:    testURL,
					Host:   testHost,
					Header: http.Header{"Authorization": []string{"Bearer " + testSecret}},
				},
				respStatusCode: http.StatusUnauthorized,
				t:              t,
			},
			want: veles.ValidationInvalid,
		},
		{
			desc: "failed_response",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				Endpoint:   testURLStr,
				HTTPMethod: http.MethodGet,
				HTTPHeaders: func(s velestest.FakeStringSecret) map[string]string {
					return map[string]string{"Authorization": "Bearer " + s.Value}
				},
				ValidResponseCodes:   []int{http.StatusOK},
				InvalidResponseCodes: []int{http.StatusUnauthorized},
			},
			secret: testSecret,
			transport: &mockRoundTripper{
				want: &http.Request{
					Method: http.MethodGet,
					URL:    testURL,
					Host:   testHost,
					Header: http.Header{"Authorization": []string{"Bearer " + testSecret}},
				},
				respStatusCode: http.StatusInternalServerError,
				t:              t,
			},
			want:    veles.ValidationFailed,
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "custom_body_parsing_valid_response",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				Endpoint: testURLStr,
				HTTPHeaders: func(s velestest.FakeStringSecret) map[string]string {
					return map[string]string{"Authorization": "Bearer " + s.Value}
				},
				StatusFromResponseBody: func(body io.Reader) (veles.ValidationStatus, error) {
					content, err := io.ReadAll(body)
					if err != nil {
						return veles.ValidationFailed, err
					}
					if string(content) == "valid_secret" {
						return veles.ValidationValid, nil
					}
					return veles.ValidationInvalid, nil
				},
			},
			secret: testSecret,
			transport: &mockRoundTripper{
				want: &http.Request{
					Method: http.MethodGet,
					URL:    testURL,
					Host:   testHost,
					Header: http.Header{"Authorization": []string{"Bearer " + testSecret}},
				},
				respStatusCode: http.StatusOK,
				respBody:       []byte("valid_secret"),
				t:              t,
			},
			want: veles.ValidationValid,
		},
		{
			desc: "custom_body_parsing_invalid_response",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				Endpoint: testURLStr,
				HTTPHeaders: func(s velestest.FakeStringSecret) map[string]string {
					return map[string]string{"Authorization": "Bearer " + s.Value}
				},
				StatusFromResponseBody: func(body io.Reader) (veles.ValidationStatus, error) {
					content, err := io.ReadAll(body)
					if err != nil {
						return veles.ValidationFailed, err
					}
					if string(content) == "valid_secret" {
						return veles.ValidationValid, nil
					}
					return veles.ValidationInvalid, nil
				},
			},
			secret: testSecret,
			transport: &mockRoundTripper{
				want: &http.Request{
					Method: http.MethodGet,
					URL:    testURL,
					Host:   testHost,
					Header: http.Header{"Authorization": []string{"Bearer " + testSecret}},
				},
				respStatusCode: http.StatusOK,
				respBody:       []byte("not_a_valid_secret"),
				t:              t,
			},
			want: veles.ValidationInvalid,
		},
		{
			desc: "valid_response_with_endpointfunc",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				EndpointFunc: func(s velestest.FakeStringSecret) (string, error) {
					return testURLStr + "?token=" + s.Value, nil
				},
				HTTPMethod:         http.MethodGet,
				ValidResponseCodes: []int{http.StatusOK},
			},
			secret: testSecret,
			transport: &mockRoundTripper{
				want: &http.Request{
					Method: http.MethodGet,
					URL:    mustParse(testURLStr + "?token=" + testSecret),
					Host:   testHost,
					Header: http.Header{},
				},
				respStatusCode: http.StatusOK,
				t:              t,
			},
			want: veles.ValidationValid,
		},
		{
			desc: "endpoint_and_endpointfunc_provided",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				Endpoint: testURLStr,
				EndpointFunc: func(s velestest.FakeStringSecret) (string, error) {
					return testURLStr, nil
				},
				HTTPMethod: http.MethodGet,
			},
			secret: testSecret,
			transport: &mockRoundTripper{
				t: t,
			},
			want:    veles.ValidationFailed,
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "no_endpoint_or_endpointfunc_provided",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				HTTPMethod: http.MethodGet,
			},
			secret: testSecret,
			transport: &mockRoundTripper{
				t: t,
			},
			want:    veles.ValidationFailed,
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "body_func_returns_error",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				Endpoint:   testURLStr,
				HTTPMethod: http.MethodPost,
				Body: func(s velestest.FakeStringSecret) (string, error) {
					return "", errors.New("body construction failed")
				},
			},
			secret: testSecret,
			transport: &mockRoundTripper{
				t: t,
			},
			want:    veles.ValidationFailed,
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "endpointfunc_returns_error",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				EndpointFunc: func(s velestest.FakeStringSecret) (string, error) {
					return "", errors.New("endpoint construction failed")
				},
				HTTPMethod: http.MethodGet,
			},
			secret: testSecret,
			transport: &mockRoundTripper{
				t: t,
			},
			want:    veles.ValidationFailed,
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "multiple_endpoints_second_valid",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				Endpoints:            []string{url1, url2},
				HTTPMethod:           http.MethodGet,
				ValidResponseCodes:   []int{http.StatusOK},
				InvalidResponseCodes: []int{http.StatusUnauthorized},
			},
			secret: testSecret,
			transport: &multiRoundTripper{
				wantRequests: []*http.Request{
					{
						Method: http.MethodGet,
						URL:    mustParse(url1),
						Host:   "endpoint1",
					},
					{
						Method: http.MethodGet,
						URL:    mustParse(url2),
						Host:   "endpoint2",
					},
				},
				statusCodes: []int{
					http.StatusUnauthorized,
					http.StatusOK,
				},
				respBodies: [][]byte{{}, {}},
				t:          t,
			},
			want: veles.ValidationValid,
		},
		{
			desc: "multiple_endpoints_all_invalid",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				Endpoints:            []string{url1, url2},
				HTTPMethod:           http.MethodGet,
				ValidResponseCodes:   []int{http.StatusOK},
				InvalidResponseCodes: []int{http.StatusUnauthorized},
			},
			secret: testSecret,
			transport: &multiRoundTripper{
				wantRequests: []*http.Request{
					{
						Method: http.MethodGet,
						URL:    mustParse(url1),
						Host:   "endpoint1",
					},
					{
						Method: http.MethodGet,
						URL:    mustParse(url2),
						Host:   "endpoint2",
					},
				},
				statusCodes: []int{
					http.StatusUnauthorized,
					http.StatusUnauthorized,
				},
				respBodies: [][]byte{{}, {}},
				t:          t,
			},
			want: veles.ValidationInvalid,
		},
		{
			desc: "multiple_endpoints_first_valid_stops_early",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				Endpoints:          []string{url1, url2},
				HTTPMethod:         http.MethodGet,
				ValidResponseCodes: []int{http.StatusOK},
			},
			secret: testSecret,
			transport: &multiRoundTripper{
				wantRequests: []*http.Request{
					{
						Method: http.MethodGet,
						URL:    mustParse(url1),
						Host:   "endpoint1",
					},
				},
				statusCodes: []int{http.StatusOK},
				respBodies:  [][]byte{{}},
				t:           t,
			},
			want: veles.ValidationValid,
		},
		{
			desc: "endpointsfunc_returns_multiple",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				EndpointsFunc: func(s velestest.FakeStringSecret) ([]string, error) {
					return []string{url1, url2}, nil
				},
				HTTPMethod:         http.MethodGet,
				ValidResponseCodes: []int{http.StatusOK},
			},
			secret: testSecret,
			transport: &multiRoundTripper{
				wantRequests: []*http.Request{
					{
						Method: http.MethodGet,
						URL:    mustParse(url1),
						Host:   "endpoint1",
					},
				},
				statusCodes: []int{http.StatusOK},
				respBodies:  [][]byte{{}},
				t:           t,
			},
			want: veles.ValidationValid,
		},
		{
			desc: "endpoints_and_endpointfuncs_provided",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				Endpoints: []string{url1},
				EndpointsFunc: func(s velestest.FakeStringSecret) ([]string, error) {
					return []string{url2}, nil
				},
				HTTPMethod: http.MethodGet,
			},
			secret:  testSecret,
			want:    veles.ValidationFailed,
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "endpoint_and_endpoints_provided",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				Endpoint:   testURLStr,
				Endpoints:  []string{url1},
				HTTPMethod: http.MethodGet,
			},
			secret:  testSecret,
			want:    veles.ValidationFailed,
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "endpoint_and_endpointfuncs_provided",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				Endpoint: testURLStr,
				EndpointsFunc: func(s velestest.FakeStringSecret) ([]string, error) {
					return []string{url1}, nil
				},
				HTTPMethod: http.MethodGet,
			},
			secret:  testSecret,
			want:    veles.ValidationFailed,
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "endpointsfunc_returns_error",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				EndpointsFunc: func(s velestest.FakeStringSecret) ([]string, error) {
					return nil, errors.New("failed to build endpoints")
				},
				HTTPMethod: http.MethodGet,
			},
			secret:  testSecret,
			want:    veles.ValidationFailed,
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "no_endpoints_or_endpointsfunc_provided",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				HTTPMethod: http.MethodGet,
			},
			secret:  testSecret,
			want:    veles.ValidationFailed,
			wantErr: cmpopts.AnyError,
		},
		{
			desc:      "no_endpoint_or_endpointfunc_or_endpoints_or_endpointsfunc_provided",
			validator: &sv.Validator[velestest.FakeStringSecret]{},
			secret:    testSecret,
			want:      veles.ValidationFailed,
			wantErr:   cmpopts.AnyError,
		},
		{
			desc: "valid_response_with_endpointsfunc",
			validator: &sv.Validator[velestest.FakeStringSecret]{
				EndpointsFunc: func(s velestest.FakeStringSecret) ([]string, error) {
					return []string{url1}, nil
				},
				HTTPMethod:         http.MethodGet,
				ValidResponseCodes: []int{http.StatusOK},
			},
			secret: testSecret,
			transport: &multiRoundTripper{
				wantRequests: []*http.Request{
					{
						Method: http.MethodGet,
						URL:    mustParse(url1),
						Host:   "endpoint1",
					},
				},
				statusCodes: []int{http.StatusOK},
				respBodies:  [][]byte{{}},
				t:           t,
			},
			want: veles.ValidationValid,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.transport != nil {
				tc.validator.HTTPC = &http.Client{Transport: tc.transport}
			}

			secret := velestest.FakeStringSecret{Value: tc.secret}
			got, err := tc.validator.Validate(t.Context(), secret)
			if !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Validate() error: got %v, want %v\n", err, tc.wantErr)
			}

			if got != tc.want {
				t.Errorf("Validate() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidate_respectsContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	validator := &sv.Validator[velestest.FakeStringSecret]{
		HTTPC:      srv.Client(),
		Endpoint:   "https://test",
		HTTPMethod: http.MethodGet,
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	secret := velestest.FakeStringSecret{Value: "abcd"}
	if _, err := validator.Validate(ctx, secret); !errors.Is(err, context.Canceled) {
		t.Errorf("Validate() error: %v, want context.Canceled", err)
	}
}
