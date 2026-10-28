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

package baseimage_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/imagedsl"
	"github.com/google/osv-scalibr/enricher/baseimage"
)

type callOutcome struct {
	resp *baseimage.Response
	err  error
}

type chainExpectation struct {
	outcomes []callOutcome
	calls    int
}

// clientFake is a concurrency-safe fake deps.dev client driven by `depsdev=...` layer attributes
// in an imagedsl.Spec.
type clientFake struct {
	mu           sync.Mutex
	expectations map[string]*chainExpectation
}

// mustClientFromSpec builds a clientFake from `depsdev=...` attributes across all images in spec:
//   - omitted, `-`, or `none`: returns an empty response (1 expected query)
//   - `repo1,repo2`: returns matching repositories (1 expected query)
//   - `ERROR`: returns clientErr (1 expected query)
//   - `CACHED`: expects 0 additional RPCs because an earlier image already cached this ChainID
func mustClientFromSpec(tb testing.TB, spec *imagedsl.Spec, clientErr error) *clientFake {
	tb.Helper()
	c := &clientFake{
		expectations: make(map[string]*chainExpectation),
	}

	for _, img := range spec.Images {
		chainIDs := img.EmptyInclusiveChainIDs()
		for i, l := range img.Layers {
			val := strings.TrimSpace(l.Attrs["depsdev"])
			cid := chainIDs[i].String()

			if strings.EqualFold(val, "CACHED") {
				if _, exists := c.expectations[cid]; !exists {
					tb.Fatalf("image %d layer %d (%q) marked depsdev=CACHED before ChainID %q was seen", img.Index, l.Index, l.Name, cid)
				}
				continue
			}

			exp, exists := c.expectations[cid]
			if !exists {
				exp = &chainExpectation{}
				c.expectations[cid] = exp
			}

			var outcome callOutcome
			if strings.EqualFold(val, "ERROR") {
				outcome.err = clientErr
			} else if val != "" && val != "-" && val != "none" {
				var results []*baseimage.Result
				for _, repo := range strings.Split(val, ",") {
					results = append(results, &baseimage.Result{Repository: strings.TrimSpace(repo)})
				}
				outcome.resp = &baseimage.Response{Results: results}
			}
			exp.outcomes = append(exp.outcomes, outcome)
		}
	}

	return c
}

func (c *clientFake) QueryContainerImages(_ context.Context, req *baseimage.Request) (*baseimage.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	exp, ok := c.expectations[req.ChainID]
	if !ok {
		c.expectations[req.ChainID] = &chainExpectation{calls: 1}
		return nil, fmt.Errorf("unexpected QueryContainerImages call for unknown ChainID %q", req.ChainID)
	}
	idx := exp.calls
	exp.calls++
	if idx >= len(exp.outcomes) {
		return nil, fmt.Errorf("unexpected extra QueryContainerImages call for ChainID %q: got %d calls, want at most %d", req.ChainID, exp.calls, len(exp.outcomes))
	}
	return exp.outcomes[idx].resp, exp.outcomes[idx].err
}

func (c *clientFake) AssertExpectations(tb testing.TB, hadError bool) {
	tb.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()

	for cid, exp := range c.expectations {
		maxCalls := len(exp.outcomes)
		// When a query errors, errgroup may cancel sibling goroutines before they run (< maxCalls),
		// but unknown or over-limit calls (> maxCalls) are always a bug.
		if exp.calls > maxCalls || (!hadError && exp.calls != maxCalls) {
			tb.Errorf("ChainID %q queried %d times, want %d", cid, exp.calls, maxCalls)
		}
	}
}
