package extracttest

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
)

func TestInventoryCmpLess(t *testing.T) {
	t.Parallel()

	type args struct {
		a *extractor.Inventory
		b *extractor.Inventory
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Location difference",
			args: args{
				a: &extractor.Inventory{
					Name:      "a",
					Version:   "2.0.0",
					Locations: []string{"aaa/bbb"},
				},
				b: &extractor.Inventory{
					Name:      "a",
					Version:   "1.0.0",
					Locations: []string{"ccc/ddd"},
				},
			},
			want: true,
		},
		{
			name: "Version difference",
			args: args{
				a: &extractor.Inventory{
					Name:      "a",
					Version:   "2.0.0",
					Locations: []string{"aaa/bbb"},
				},
				b: &extractor.Inventory{
					Name:      "a",
					Version:   "1.0.0",
					Locations: []string{"aaa/bbb"},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InventoryCmpLess(tt.args.a, tt.args.b); got != tt.want {
				t.Errorf("InventoryCmpLess() = %v, want %v", got, tt.want)
			}
		})
	}
}
