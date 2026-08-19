package aspect

import "testing"

func TestCleanVersion(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{"1.2.3", "1.2.3"},
		{"1.2.3.tar.gz", "1.2.3"},
		{"1.2.3.zip", "1.2.3"},
		{" 1.2.3/ ", "1.2.3"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			if got := cleanVersion(tt.version); got != tt.want {
				t.Errorf("cleanVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractVersionFromURL(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://example.com/v1.2.3/foo.tar.gz", "1.2.3"},
		{"https://example.com/foo-1.2.3.tar.gz", "1.2.3"},
		{"https://example.com/foo-20231012.zip", "20231012"},
		{"https://example.com/foo", ""},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := extractVersionFromURL(tt.url); got != tt.want {
				t.Errorf("extractVersionFromURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractVersionFromStripPrefix(t *testing.T) {
	tests := []struct {
		stripPrefix string
		want        string
	}{
		{"foo-1.2.3", "1.2.3"},
		{"foo-v1.2.3", "1.2.3"},
		{"foo-1.2", "1.2"},
		{"foo", ""},
	}
	for _, tt := range tests {
		t.Run(tt.stripPrefix, func(t *testing.T) {
			if got := extractVersionFromStripPrefix(tt.stripPrefix); got != tt.want {
				t.Errorf("extractVersionFromStripPrefix() = %v, want %v", got, tt.want)
			}
		})
	}
}
