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

func TestValidate(t *testing.T) {
	testSecret := "TEST-SECRET"
	testURLStr := "https://test"
	testHost := "test"
	testURL, err := url.Parse(testURLStr)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", testURLStr, err)
	}

	tests := []struct {
		desc         string
		opts         []sv.Option[velestest.FakeStringSecret]
		secret       string
		roundTripper *mockRoundTripper
		want         veles.ValidationStatus
		wantErr      error
	}{
		{
			desc: "valid_response",
			opts: []sv.Option[velestest.FakeStringSecret]{
				sv.WithEndpoint[velestest.FakeStringSecret](testURLStr),
				sv.WithHTTPMethod[velestest.FakeStringSecret](http.MethodGet),
				sv.WithHTTPHeaders(func(s velestest.FakeStringSecret) map[string]string {
					return map[string]string{"Authorization": "Bearer " + s.Value}
				}),
				sv.WithValidResponseCodes[velestest.FakeStringSecret]([]int{http.StatusOK}),
			},
			secret: testSecret,
			roundTripper: &mockRoundTripper{
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
			opts: []sv.Option[velestest.FakeStringSecret]{
				sv.WithEndpoint[velestest.FakeStringSecret](testURLStr),
				sv.WithHTTPMethod[velestest.FakeStringSecret](http.MethodGet),
				sv.WithHTTPHeaders(func(s velestest.FakeStringSecret) map[string]string {
					return map[string]string{"Authorization": "Bearer " + s.Value}
				}),
				sv.WithValidResponseCodes[velestest.FakeStringSecret]([]int{http.StatusOK}),
				sv.WithInvalidResponseCodes[velestest.FakeStringSecret]([]int{http.StatusUnauthorized}),
			},
			secret: testSecret,
			roundTripper: &mockRoundTripper{
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
			opts: []sv.Option[velestest.FakeStringSecret]{
				sv.WithEndpoint[velestest.FakeStringSecret](testURLStr),
				sv.WithHTTPMethod[velestest.FakeStringSecret](http.MethodGet),
				sv.WithHTTPHeaders(func(s velestest.FakeStringSecret) map[string]string {
					return map[string]string{"Authorization": "Bearer " + s.Value}
				}),
				sv.WithValidResponseCodes[velestest.FakeStringSecret]([]int{http.StatusOK}),
				sv.WithInvalidResponseCodes[velestest.FakeStringSecret]([]int{http.StatusUnauthorized}),
			},
			secret: testSecret,
			roundTripper: &mockRoundTripper{
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
			opts: []sv.Option[velestest.FakeStringSecret]{
				sv.WithEndpoint[velestest.FakeStringSecret](testURLStr),
				sv.WithHTTPHeaders(func(s velestest.FakeStringSecret) map[string]string {
					return map[string]string{"Authorization": "Bearer " + s.Value}
				}),
				sv.WithStatusFromResponseBody[velestest.FakeStringSecret](
					func(body []byte) (veles.ValidationStatus, error) {
						if string(body) == "valid_secret" {
							return veles.ValidationValid, nil
						}
						return veles.ValidationInvalid, nil
					}),
			},
			secret: testSecret,
			roundTripper: &mockRoundTripper{
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
			opts: []sv.Option[velestest.FakeStringSecret]{
				sv.WithEndpoint[velestest.FakeStringSecret](testURLStr),
				sv.WithHTTPHeaders(func(s velestest.FakeStringSecret) map[string]string {
					return map[string]string{"Authorization": "Bearer " + s.Value}
				}),
				sv.WithStatusFromResponseBody[velestest.FakeStringSecret](
					func(body []byte) (veles.ValidationStatus, error) {
						if string(body) == "valid_secret" {
							return veles.ValidationValid, nil
						}
						return veles.ValidationInvalid, nil
					}),
			},
			secret: testSecret,
			roundTripper: &mockRoundTripper{
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
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			validator := sv.New[velestest.FakeStringSecret](
				append(tc.opts,
					sv.WithClient[velestest.FakeStringSecret](&http.Client{Transport: tc.roundTripper}),
				)...,
			)

			secret := velestest.FakeStringSecret{Value: tc.secret}
			got, err := validator.Validate(t.Context(), secret)
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

	validator := sv.New(
		sv.WithClient[velestest.FakeStringSecret](srv.Client()),
		sv.WithEndpoint[velestest.FakeStringSecret]("https://test"),
		sv.WithHTTPMethod[velestest.FakeStringSecret](http.MethodGet),
	)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	secret := velestest.FakeStringSecret{Value: "abcd"}
	if _, err := validator.Validate(ctx, secret); !errors.Is(err, context.Canceled) {
		t.Errorf("Validate() error: %v, want context.Canceled", err)
	}
}
