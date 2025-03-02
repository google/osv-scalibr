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

//go:build !windows

package winlocal

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestScan(t *testing.T) {
	d := Detector{}
	_, err := d.Scan(t.Context(), nil, nil)
	if diff := cmp.Diff(err.Error(), "only supported on Windows"); diff != "" {
		t.Errorf("Scan(...) unexpected error (-want +got): %v", diff)
	}
}
