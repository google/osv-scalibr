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

package baseimage_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/enricher/baseimage"
)

type reqRespErr struct {
	req  *baseimage.Request
	resp *baseimage.Response
	err  error
}

type config struct {
	ReqRespErrs []reqRespErr
}

type clientFake struct {
	reqRespErrs []reqRespErr
	reqNum      int
}

func newClientFake(cfg *config) (*clientFake, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}
	// Defense copy to avoid mutating the config.
	reqRespErrs := make([]reqRespErr, len(cfg.ReqRespErrs))
	copy(reqRespErrs, cfg.ReqRespErrs)
	client := &clientFake{
		reqRespErrs: reqRespErrs,
	}
	return client, nil
}

func mustNewClientFake(t *testing.T, cfg *config) *clientFake {
	t.Helper()
	baseImageClientFake, err := newClientFake(cfg)
	if err != nil {
		t.Fatalf("Failed to create base image client: %v", err)
	}
	return baseImageClientFake
}

func (c *clientFake) QueryContainerImages(ctx context.Context, req *baseimage.Request) (*baseimage.Response, error) {
	defer func() { c.reqNum++ }()

	if c.reqNum >= len(c.reqRespErrs) {
		return nil, errors.New("out of range")
	}

	rre := c.reqRespErrs[c.reqNum]
	wantReq := rre.req
	if diff := cmp.Diff(wantReq, req); diff != "" {
		return nil, fmt.Errorf("expected request  diff (-want +got):\n%s", diff)
	}

	return rre.resp, rre.err
}
