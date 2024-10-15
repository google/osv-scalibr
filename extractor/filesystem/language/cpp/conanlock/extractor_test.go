package conanlock_test

import (
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem/language/cpp/conanlock"
)

func TestExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			name:      "",
			inputPath: "conan.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/conan.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/conan.lock/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/conan.lock.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.conan.lock",
			want:      false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := conanlock.Extractor{}
			got := e.FileRequired(tt.inputPath, nil)
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}