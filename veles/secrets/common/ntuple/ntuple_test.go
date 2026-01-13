package ntuple_test

import (
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/ntuple"
)

type mockSecret struct {
	Value string
}

// implement veles.Secret
func (m mockSecret) ValueBytes() []byte { return []byte(m.Value) }

// full tuple converter
func mockSecretFromTuple(ms []ntuple.Match) (veles.Secret, bool) {
	if len(ms) == 3 {
		return mockSecret{
			Value: string(ms[0].Value) + "-" + string(ms[1].Value) + "-" + string(ms[2].Value),
		}, true
	}
	return nil, false
}

// partial tuple converter
func mockSecretFromPartial(m ntuple.Match) (veles.Secret, bool) {
	return mockSecret{Value: string(m.Value)}, true
}

func TestNTupleDetection(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		maxDistance uint32
		fromPartial func(ntuple.Match) (veles.Secret, bool)
		want        []veles.Secret
		wantPos     []int
	}{
		{
			name:        "simple_triple",
			input:       "a1 b1 c1",
			maxDistance: 1000,
			want: []veles.Secret{
				mockSecret{Value: "a1-b1-c1"},
			},
			wantPos: []int{0},
		},
		{
			name:        "multiple_triples",
			input:       "a1 b1 c1   a2 b2 c2",
			maxDistance: 1000,
			want: []veles.Secret{
				mockSecret{Value: "a1-b1-c1"},
				mockSecret{Value: "a2-b2-c2"},
			},
			wantPos: []int{0, 11},
		},
		{
			name:        "missing_c - no full tuple",
			input:       "a1 b1",
			maxDistance: 1000,
			want:        nil,
		},
		{
			name:        "far_apart - no tuple",
			input:       "a1           b1          c1",
			maxDistance: 5,
			want:        nil,
		},
		{
			name:        "partial_allowed",
			input:       "a1",
			maxDistance: 1000,
			fromPartial: mockSecretFromPartial,
			want: []veles.Secret{
				mockSecret{Value: "a1"},
			},
			wantPos: []int{0},
		},
		{
			name:        "overlap_resolution",
			input:       " b2 ab1 c1",
			maxDistance: 1000,
			fromPartial: mockSecretFromPartial,
			want: []veles.Secret{
				mockSecret{Value: "ab1-b1-c1"},
			},
			wantPos: []int{4},
		},
	}

	aPattern := regexp.MustCompile(`a[a-z]*[0-9]`)
	bPattern := regexp.MustCompile(`b[a-z]*[0-9]`)
	cPattern := regexp.MustCompile(`c[a-z]*[0-9]`)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &ntuple.Detector{
				MaxElementLen: 10,
				MaxDistance:   tt.maxDistance,
				Finders: []ntuple.Finder{
					ntuple.FindAllMatches(aPattern),
					ntuple.FindAllMatches(bPattern),
					ntuple.FindAllMatches(cPattern),
				},
				FromTuple:   mockSecretFromTuple,
				FromPartial: tt.fromPartial,
			}

			got, pos := d.Detect([]byte(tt.input))

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Secrets mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantPos, pos); diff != "" {
				t.Errorf("Positions mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
