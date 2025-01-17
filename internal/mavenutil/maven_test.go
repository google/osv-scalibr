package mavenutil_test

import (
	"testing"

	"github.com/google/osv-scalibr/internal/mavenutil"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestParentPOMPath(t *testing.T) {
	input := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{})
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
			currentPath:  "fixtures/my-app/pom.xml",
			relativePath: "../parent/pom.xml",
			want:         "fixtures/parent/pom.xml",
		},
		{
			// Wrong file name is specified in relative path.
			currentPath:  "fixtures/my-app/pom.xml",
			relativePath: "../parent/abc.xml",
			want:         "",
		},
		{
			// Wrong directory is specified in relative path.
			currentPath:  "fixtures/my-app/pom.xml",
			relativePath: "../not-found/pom.xml",
			want:         "",
		},
		{
			// Only directory is specified.
			currentPath:  "fixtures/my-app/pom.xml",
			relativePath: "../parent",
			want:         "fixtures/parent/pom.xml",
		},
		{
			// Parent relative path is default to '../pom.xml'.
			currentPath:  "fixtures/my-app/pom.xml",
			relativePath: "",
			want:         "fixtures/pom.xml",
		},
		{
			// No pom.xml is found even in the default path.
			currentPath:  "fixtures/pom.xml",
			relativePath: "",
			want:         "",
		},
	}
	for _, tt := range tests {
		got := mavenutil.ParentPOMPath(&input, tt.currentPath, tt.relativePath)
		if got != tt.want {
			t.Errorf("ParentPOMPath(%s, %s): got %s, want %s", tt.currentPath, tt.relativePath, got, tt.want)
		}
	}
}
