package mavenutil_test

import (
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/internal/mavenutil"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestParentPOMPath(t *testing.T) {
	input := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
		Path: filepath.Join("fixtures", "my-app", "pom.xml"),
	})
	defer extracttest.CloseTestScanInput(t, input)

	tests := []struct {
		currentPath, relativePath string
		want                      string
	}{
		// fixtures
		// |- maven
		// |  |- my-app
		// |  |  |- pom.xml
		// |  |- parent
		// |  |  |- pom.xml
		// |- pom.xml
		{
			// Parent path is specified correctly.
			currentPath:  filepath.Join("fixtures", "my-app", "pom.xml"),
			relativePath: "../parent/pom.xml",
			want:         filepath.Join("fixtures", "parent", "pom.xml"),
		},
		{
			// Wrong file name is specified in relative path.
			currentPath:  filepath.Join("fixtures", "my-app", "pom.xml"),
			relativePath: "../parent/abc.xml",
			want:         "",
		},
		{
			// Wrong directory is specified in relative path.
			currentPath:  filepath.Join("fixtures", "my-app", "pom.xml"),
			relativePath: "../not-found/pom.xml",
			want:         "",
		},
		{
			// Only directory is specified.
			currentPath:  filepath.Join("fixtures", "my-app", "pom.xml"),
			relativePath: "../parent",
			want:         filepath.Join("fixtures", "parent", "pom.xml"),
		},
		{
			// Parent relative path is default to '../pom.xml'.
			currentPath:  filepath.Join("fixtures", "my-app", "pom.xml"),
			relativePath: "",
			want:         filepath.Join("fixtures", "pom.xml"),
		},
		{
			// No pom.xml is found even in the default path.
			currentPath:  filepath.Join("fixtures", "pom.xml"),
			relativePath: "",
			want:         "",
		},
	}
	for _, tt := range tests {
		got := mavenutil.ParentPOMPath(&input, tt.currentPath, tt.relativePath)
		if got != filepath.ToSlash(tt.want) {
			t.Errorf("ParentPOMPath(%s, %s): got %s, want %s", tt.currentPath, tt.relativePath, got, tt.want)
		}
	}
}
