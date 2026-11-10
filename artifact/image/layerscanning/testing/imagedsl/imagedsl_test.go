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

package imagedsl_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/imagedsl"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
)

func TestParseAndToInventory(t *testing.T) {
	spec := imagedsl.MustParse(t, `
		# Base OS image
		layer L0 depsdev=alpine
		=== base gcr.io/ns/custom-alpine plugin=other chain_id=sha256:custom ===
		empty-layer
		layer L1 depsdev=nginx
		=== base gcr.io/buildpacks-run plugin=buildpacks ===
		=== base docker.io/nginx ===
		layer L2
	`)
	inv := spec.ToInventory()

	d0 := digest.FromString("L0")
	d1 := digest.FromString("L1")
	d2 := digest.FromString("L2")

	wantLayerChain1 := identity.ChainID([]digest.Digest{d0, d1})
	wantLayerChain2 := identity.ChainID([]digest.Digest{d0, d1, d2})
	wantEmptyInclChain1 := identity.ChainID([]digest.Digest{d0, imagedsl.DigestSHA256EmptyTar, d1})

	want := &inventory.Inventory{
		ContainerImageMetadata: []*extractor.ContainerImageMetadata{{
			Index: 0,
			LayerMetadata: []*extractor.LayerMetadata{
				{Index: 0, DiffID: d0, ChainID: d0, BaseImageIndex: 2},
				{Index: 1, IsEmpty: true, BaseImageIndex: 1},
				{Index: 2, DiffID: d1, ChainID: wantLayerChain1, BaseImageIndex: 1},
				{Index: 3, DiffID: d2, ChainID: wantLayerChain2, BaseImageIndex: 0},
			},
			BaseImages: [][]*extractor.BaseImageDetails{
				{},
				{
					{Repository: "buildpacks-run", Registry: "gcr.io", Plugin: "buildpacks", ChainID: wantEmptyInclChain1},
					{Repository: "nginx", Registry: "docker.io", Plugin: "baseimage", ChainID: wantEmptyInclChain1},
				},
				{
					{Repository: "ns/custom-alpine", Registry: "gcr.io", Plugin: "other", ChainID: "sha256:custom"},
				},
			},
		}},
	}

	if diff := cmp.Diff(want, inv, imagedsl.DiffOptions()...); diff != "" {
		t.Fatalf("ToInventory() diff (-want +got):\n%s", diff)
	}
	for i, lm := range inv.ContainerImageMetadata[0].LayerMetadata {
		if lm.ParentContainer != inv.ContainerImageMetadata[0] {
			t.Errorf("LayerMetadata[%d].ParentContainer was not set to parent ContainerImageMetadata", i)
		}
	}
}

func TestToEnrichedInventory(t *testing.T) {
	if diff := cmp.Diff(&inventory.Inventory{}, imagedsl.MustParse(t, "").ToEnrichedInventory()); diff != "" {
		t.Errorf("empty ToEnrichedInventory() diff (-want +got):\n%s", diff)
	}

	spec := imagedsl.MustParse(t, `
		image 3
		layer L0 diff_id=sha256:explicit
		layer L1 diff_id=none
	`)
	if got := spec.ToInventory().ContainerImageMetadata[0].BaseImages; got != nil {
		t.Errorf("ToInventory() BaseImages = %v, want nil when no base checkpoints exist", got)
	}

	want := &inventory.Inventory{
		ContainerImageMetadata: []*extractor.ContainerImageMetadata{{
			Index: 3,
			LayerMetadata: []*extractor.LayerMetadata{
				{Index: 0, DiffID: "sha256:explicit", ChainID: "sha256:explicit", BaseImageIndex: 0},
				{Index: 1, BaseImageIndex: 0},
			},
			BaseImages: [][]*extractor.BaseImageDetails{{}},
		}},
	}
	if diff := cmp.Diff(want, spec.ToEnrichedInventory(), imagedsl.DiffOptions()...); diff != "" {
		t.Errorf("ToEnrichedInventory() diff (-want +got):\n%s", diff)
	}
}

func TestParseMultiImageAndAttrs(t *testing.T) {
	spec := imagedsl.MustParse(t, `
		image
		layer alpine depsdev=alpine

		image
		layer alpine depsdev=CACHED
	`)
	dAlpine := digest.FromString("alpine")
	want := &imagedsl.Spec{
		Images: []*imagedsl.ImageSpec{
			{
				Index:  0,
				Layers: []*imagedsl.LayerSpec{{Index: 0, Name: "alpine", DiffID: dAlpine, Attrs: map[string]string{"depsdev": "alpine"}}},
			},
			{
				Index:  1,
				Layers: []*imagedsl.LayerSpec{{Index: 0, Name: "alpine", DiffID: dAlpine, Attrs: map[string]string{"depsdev": "CACHED"}}},
			},
		},
	}
	if diff := cmp.Diff(want, spec); diff != "" {
		t.Errorf("MustParse() diff (-want +got):\n%s", diff)
	}
}

func TestParseHistory(t *testing.T) {
	histories, wantIdx, hasWant := imagedsl.MustParseHistory(t, `
		layer       ADD rootfs.tar.xz /
		empty-layer CMD ["bash"]           <-- want
		layer       /bin/sh -c #(nop) COPY app /app
		empty-layer CMD ["/app"]
	`)
	if !hasWant || wantIdx != 1 {
		t.Errorf("MustParseHistory() wantIdx=%d, hasWant=%v; want 1, true", wantIdx, hasWant)
	}
	want := []v1.History{
		{CreatedBy: "ADD rootfs.tar.xz /", EmptyLayer: false},
		{CreatedBy: `CMD ["bash"]`, EmptyLayer: true},
		{CreatedBy: "/bin/sh -c #(nop) COPY app /app", EmptyLayer: false},
		{CreatedBy: `CMD ["/app"]`, EmptyLayer: true},
	}
	if diff := cmp.Diff(want, histories); diff != "" {
		t.Errorf("MustParseHistory() diff (-want +got):\n%s", diff)
	}

	if _, _, hasWant = imagedsl.MustParseHistory(t, "layer ADD rootfs.tar.xz /"); hasWant {
		t.Errorf("MustParseHistory() without marker: hasWant = true, want false")
	}
}

func TestParseErrors(t *testing.T) {
	for _, tc := range []struct {
		dsl      string
		wantLine string
	}{
		{"=== unclosed", "line 1:"},
		{"===   ===", "line 1:"},
		{"image bad", "line 1:"},
		{"layer depsdev=alpine", "line 1:"},
		{"=== base docker.io/alpine ===", "line 1:"},
		{"layer L0\n=== base invalid_no_slash ===", "line 2:"},
		{"unknown_directive", "line 1:"},
	} {
		if _, err := imagedsl.Parse(tc.dsl); err == nil || !strings.Contains(err.Error(), tc.wantLine) {
			t.Errorf("Parse(%q) error = %v, want error containing %q", tc.dsl, err, tc.wantLine)
		}
	}

	for _, dsl := range []string{
		"invalid prefix",
		"layer CMD 1 <-- want\nlayer CMD 2 <-- want",
	} {
		if got, wantIdx, hasWant, err := imagedsl.ParseHistory(dsl); err == nil {
			t.Errorf("ParseHistory(%q) = (%v, %d, %v, nil), want error", dsl, got, wantIdx, hasWant)
		}
	}
}
