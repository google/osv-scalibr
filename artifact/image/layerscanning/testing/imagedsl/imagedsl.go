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

// Package imagedsl parses a lightweight timeline DSL for container base-image tests.
//
// Layers are written top-to-bottom in chronological build order (oldest index 0 first, newest
// layer last), with `=== base ... ===` checkpoints marking cumulative base image boundaries:
//
//	layer alpine       depsdev=alpine
//	=== base docker.io/alpine ===
//	layer nginxnonedge
//	layer nginx        depsdev=nginx
//	=== base docker.io/nginx ===
package imagedsl

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
)

// DigestSHA256EmptyTar is the canonical SHA-256 digest of an empty tar archive (1024 NUL bytes),
// used when computing empty-layer-inclusive chain IDs (e.g. for deps.dev queries).
const DigestSHA256EmptyTar = digest.Digest("sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef")

// Spec is a parsed single- or multi-image test specification.
type Spec struct {
	Images []*ImageSpec
}

// ImageSpec describes a single container image in a Spec.
type ImageSpec struct {
	Index  int
	Layers []*LayerSpec
}

// LayerSpec describes a single container layer in chronological build order.
type LayerSpec struct {
	Index      int
	Name       string
	IsEmpty    bool
	DiffID     digest.Digest
	Attrs      map[string]string
	BaseImages []*BaseImageSpec
}

// BaseImageSpec describes a single BaseImageDetails entry attached to a layer boundary.
type BaseImageSpec struct {
	Registry        string
	Repository      string
	Plugin          string
	OverrideChainID bool
	CustomChainID   digest.Digest
}

// DiffOptions returns standard cmp.Options for comparing Inventory and LayerMetadata values while
// ignoring cyclic ParentContainer back-pointers.
func DiffOptions() []cmp.Option {
	return []cmp.Option{
		cmpopts.IgnoreFields(extractor.LayerMetadata{}, "ParentContainer"),
	}
}

// ResolveDigest turns a symbolic name (e.g. "alpine") into a deterministic SHA-256 digest, or
// returns s verbatim if it already contains an algorithm prefix such as "sha256:...".
func ResolveDigest(s string) digest.Digest {
	if s == "" || s == "none" {
		return ""
	}
	if strings.Contains(s, ":") {
		return digest.Digest(s)
	}
	return digest.FromString(s)
}

// MustParse parses dsl and calls tb.Fatalf if parsing fails.
func MustParse(tb testing.TB, dsl string) *Spec {
	tb.Helper()
	spec, err := Parse(dsl)
	if err != nil {
		tb.Fatalf("imagedsl.Parse failed: %v", err)
	}
	return spec
}

// Parse parses a whitespace-tokenized base-image timeline DSL into a Spec.
func Parse(dsl string) (*Spec, error) {
	spec := &Spec{}
	var curImg *ImageSpec
	var curLayer *LayerSpec

	for i, rawLine := range strings.Split(dsl, "\n") {
		lineNum := i + 1
		line, _, _ := strings.Cut(rawLine, "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "==="); ok {
			rest, ok = strings.CutSuffix(rest, "===")
			if !ok {
				return nil, fmt.Errorf("line %d: `===` divider must end with `===`", lineNum)
			}
			line = strings.TrimSpace(rest)
			if line == "" {
				return nil, fmt.Errorf("line %d: empty `===` divider", lineNum)
			}
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "image":
			idx := len(spec.Images)
			if len(fields) == 2 {
				parsed, err := strconv.Atoi(fields[1])
				if err != nil {
					//nolint:errorlint // Do not expose strconv's error type in Parse's API.
					return nil, fmt.Errorf("line %d: invalid image index %q: %v", lineNum, fields[1], err)
				}
				idx = parsed
			} else if len(fields) > 2 {
				return nil, fmt.Errorf("line %d: usage: `image [index]`", lineNum)
			}
			curImg = &ImageSpec{Index: idx}
			curLayer = nil
			spec.Images = append(spec.Images, curImg)

		case "layer", "empty-layer":
			if curImg == nil {
				curImg = &ImageSpec{Index: 0}
				spec.Images = append(spec.Images, curImg)
			}
			isEmpty := fields[0] == "empty-layer"
			ls := &LayerSpec{
				Index:   len(curImg.Layers),
				IsEmpty: isEmpty,
				Attrs:   make(map[string]string),
			}
			opts := fields[1:]
			if !isEmpty {
				if len(fields) < 2 || strings.Contains(fields[1], "=") {
					return nil, fmt.Errorf("line %d: `layer` requires a name before attributes (e.g. `layer alpine`)", lineNum)
				}
				ls.Name = fields[1]
				ls.DiffID = ResolveDigest(fields[1])
				opts = fields[2:]
			}
			for _, opt := range opts {
				k, v, ok := strings.Cut(opt, "=")
				if !ok || k == "" {
					return nil, fmt.Errorf("line %d: expected key=value attribute, got %q", lineNum, opt)
				}
				if k == "diff_id" {
					ls.DiffID = ResolveDigest(v)
				} else {
					ls.Attrs[k] = v
				}
			}
			curImg.Layers = append(curImg.Layers, ls)
			curLayer = ls

		case "base":
			if curLayer == nil {
				return nil, fmt.Errorf("line %d: `base` must follow a layer", lineNum)
			}
			if len(fields) < 2 {
				return nil, fmt.Errorf("line %d: `base` requires `<registry>/<repository>`", lineNum)
			}
			reg, repo, ok := strings.Cut(fields[1], "/")
			if !ok || reg == "" || repo == "" {
				return nil, fmt.Errorf("line %d: base image %q must have `<registry>/<repository>` format", lineNum, fields[1])
			}
			bi := &BaseImageSpec{
				Registry:   reg,
				Repository: repo,
				Plugin:     "baseimage",
			}
			for _, opt := range fields[2:] {
				k, v, hasEq := strings.Cut(opt, "=")
				if !hasEq {
					return nil, fmt.Errorf("line %d: expected key=value on `base`, got %q", lineNum, opt)
				}
				switch k {
				case "plugin":
					bi.Plugin = v
				case "chain_id":
					bi.OverrideChainID = true
					bi.CustomChainID = ResolveDigest(v)
				default:
					return nil, fmt.Errorf("line %d: unknown `base` attribute %q", lineNum, k)
				}
			}
			curLayer.BaseImages = append(curLayer.BaseImages, bi)

		default:
			return nil, fmt.Errorf("line %d: unknown directive %q", lineNum, fields[0])
		}
	}

	return spec, nil
}

// MustParseHistory parses a history DSL block (`layer <cmd>` / `empty-layer <cmd>` with an optional
// `<-- want` suffix) and calls tb.Fatalf on syntax errors.
func MustParseHistory(tb testing.TB, dsl string) ([]v1.History, int, bool) {
	tb.Helper()
	h, wantIdx, hasWant, err := ParseHistory(dsl)
	if err != nil {
		tb.Fatalf("imagedsl.ParseHistory failed: %v", err)
	}
	return h, wantIdx, hasWant
}

// ParseHistory parses a history DSL block into []v1.History and an optional wanted index.
func ParseHistory(dsl string) ([]v1.History, int, bool, error) {
	var histories []v1.History
	wantIdx := 0
	hasWant := false

	for i, rawLine := range strings.Split(dsl, "\n") {
		lineNum := i + 1
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		trimmed, isWant := strings.CutSuffix(trimmed, "<-- want")
		trimmed = strings.TrimSpace(trimmed)

		fields := strings.Fields(trimmed)
		if len(fields) == 0 || (fields[0] != "layer" && fields[0] != "empty-layer") {
			return nil, 0, false, fmt.Errorf("line %d: history line must start with `layer` or `empty-layer`: %q", lineNum, rawLine)
		}
		if isWant {
			if hasWant {
				return nil, 0, false, fmt.Errorf("line %d: multiple `<-- want` markers", lineNum)
			}
			hasWant = true
			wantIdx = len(histories)
		}
		histories = append(histories, v1.History{
			CreatedBy:  strings.TrimSpace(trimmed[len(fields[0]):]),
			EmptyLayer: fields[0] == "empty-layer",
		})
	}
	return histories, wantIdx, hasWant, nil
}

// LayerChainIDs returns standard OCI ChainIDs for each layer (skipping empty layers).
func (img *ImageSpec) LayerChainIDs() []digest.Digest {
	if len(img.Layers) == 0 {
		return nil
	}
	var nonEmpty []digest.Digest
	for _, l := range img.Layers {
		if !l.IsEmpty && l.DiffID != "" {
			nonEmpty = append(nonEmpty, l.DiffID)
		}
	}
	identity.ChainIDs(nonEmpty)
	out := make([]digest.Digest, len(img.Layers))
	j := 0
	for i, l := range img.Layers {
		if !l.IsEmpty && l.DiffID != "" {
			out[i] = nonEmpty[j]
			j++
		}
	}
	return out
}

// EmptyInclusiveChainIDs returns empty-layer-inclusive ChainIDs (matching deps.dev indexing).
func (img *ImageSpec) EmptyInclusiveChainIDs() []digest.Digest {
	if len(img.Layers) == 0 {
		return nil
	}
	ids := make([]digest.Digest, len(img.Layers))
	for i, l := range img.Layers {
		ids[i] = l.DiffID
		if ids[i] == "" {
			ids[i] = DigestSHA256EmptyTar
		}
	}
	identity.ChainIDs(ids)
	return ids
}

// ToInventory builds an inventory.Inventory from the parsed Spec (with BaseImages left nil on
// images that have no `=== base ... ===` checkpoints).
func (s *Spec) ToInventory() *inventory.Inventory {
	return s.buildInventory(false)
}

// ToEnrichedInventory builds an inventory.Inventory where every image has at least the index-0
// empty placeholder `{{}}` in BaseImages (matching baseimage.Enrich's postcondition).
func (s *Spec) ToEnrichedInventory() *inventory.Inventory {
	return s.buildInventory(true)
}

func (s *Spec) buildInventory(ensurePlaceholder bool) *inventory.Inventory {
	if len(s.Images) == 0 {
		return &inventory.Inventory{}
	}
	inv := &inventory.Inventory{
		ContainerImageMetadata: make([]*extractor.ContainerImageMetadata, 0, len(s.Images)),
	}
	for _, imgSpec := range s.Images {
		cim := &extractor.ContainerImageMetadata{
			Index:         imgSpec.Index,
			LayerMetadata: make([]*extractor.LayerMetadata, len(imgSpec.Layers)),
		}
		layerChainIDs := imgSpec.LayerChainIDs()
		emptyInclChainIDs := imgSpec.EmptyInclusiveChainIDs()
		hasBase := false

		for i, l := range imgSpec.Layers {
			if len(l.BaseImages) > 0 {
				hasBase = true
			}
			cim.LayerMetadata[i] = &extractor.LayerMetadata{
				ParentContainer: cim,
				Index:           l.Index,
				DiffID:          l.DiffID,
				ChainID:         layerChainIDs[i],
				IsEmpty:         l.IsEmpty,
			}
		}

		if hasBase || ensurePlaceholder {
			cim.BaseImages = [][]*extractor.BaseImageDetails{{}}
			for i := len(imgSpec.Layers) - 1; i >= 0; i-- {
				l := imgSpec.Layers[i]
				if len(l.BaseImages) > 0 {
					var details []*extractor.BaseImageDetails
					for _, bi := range l.BaseImages {
						cid := emptyInclChainIDs[i]
						if bi.OverrideChainID {
							cid = bi.CustomChainID
						}
						details = append(details, &extractor.BaseImageDetails{
							Repository: bi.Repository,
							Registry:   bi.Registry,
							Plugin:     bi.Plugin,
							ChainID:    cid,
						})
					}
					cim.BaseImages = append(cim.BaseImages, details)
				}
				cim.LayerMetadata[i].BaseImageIndex = len(cim.BaseImages) - 1
			}
		}
		inv.ContainerImageMetadata = append(inv.ContainerImageMetadata, cim)
	}
	return inv
}
