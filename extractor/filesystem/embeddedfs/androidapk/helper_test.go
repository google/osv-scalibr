package androidapk

import (
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/androidapk/metadata"
)

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "human readable version",
			in:   "26.12.33",
			want: "26.12.33",
		},
		{
			name: "numeric build number",
			in:   "261233000",
			want: "26.12.33",
		},
		{
			name: "trim whitespace",
			in:   " 26.12.33 ",
			want: "26.12.33",
		},
		{
			name: "empty string",
			in:   "",
			want: "",
		},
		{
			name: "8 digit version",
			in:   "12345678",
			want: "12.34.56.78",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeVersion(tt.in)
			if got != tt.want {
				t.Fatalf("normalizeVersion(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsNumericBuildNumber(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"261233000", true},
		{"1234567", true},
		{"26.12.33", false},
		{"abc123", false},
		{"12345", false},
	}

	for _, tt := range tests {
		got := isNumericBuildNumber(tt.in)
		if got != tt.want {
			t.Fatalf("isNumericBuildNumber(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestFormatNumericVersion(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"261233000", "26.12.33"},
		{"12345678", "12.34.56.78"},
		{"1234567890", "12.34.56.78.90"},
		{"12345678901", "12.34.56.78.90.1"},
		{"123456", "123456"},
	}

	for _, tt := range tests {
		got := formatNumericVersion(tt.in)
		if got != tt.want {
			t.Fatalf("formatNumericVersion(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCleanArtifactID(t *testing.T) {
	tests := []struct {
		name string
		tag  string
		pkg  string
		want string
	}{
		{
			name: "remove package prefix",
			tag:  "com.google.android.gms.ads",
			pkg:  "com.google.android.gms",
			want: "ads",
		},
		{
			name: "fallback to last segment",
			tag:  "org.example.library.maps",
			pkg:  "com.google.android.gms",
			want: "maps",
		},
		{
			name: "exact package match",
			tag:  "com.google.android.gms",
			pkg:  "com.google.android.gms",
			want: "com.google.android.gms",
		},
		{
			name: "trim dots",
			tag:  ".maps.",
			pkg:  "com.google.android.gms",
			want: "maps",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanArtifactID(tt.tag, tt.pkg)
			if got != tt.want {
				t.Fatalf("cleanArtifactID(%q, %q) = %q, want %q",
					tt.tag, tt.pkg, got, tt.want)
			}
		})
	}
}

func TestDeriveGroupID(t *testing.T) {
	manifest := &manifest{
		Package: "com.example.app",
	}

	tests := []struct {
		name       string
		tag        string
		artifactID string
		want       string
	}{
		{
			name:       "derive google play services group",
			tag:        "com.google.android.gms.ads",
			artifactID: "ads",
			want:       "com.google.android.gms",
		},
		{
			name:       "derive firebase group",
			tag:        "com.google.firebase.auth",
			artifactID: "auth",
			want:       "com.google.firebase",
		},
		{
			name:       "fallback to manifest tag",
			tag:        "invalidtag",
			artifactID: "ads",
			want:       "invalidtag",
		},
		{
			name:       "empty artifact id",
			tag:        "com.google.android.gms.ads",
			artifactID: "",
			want:       "com.google.android.gms.ads",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveGroupID(tt.tag, tt.artifactID, manifest)
			if got != tt.want {
				t.Fatalf("deriveGroupID(%q, %q) = %q, want %q",
					tt.tag, tt.artifactID, got, tt.want)
			}
		})
	}
}

func TestFindVersionInMetadata(t *testing.T) {
	metadataEntries := []metaData{
		{
			Name:  "com.google.android.gms.version",
			Value: "261233000",
		},
		{
			Name:  "com.google.firebase.auth.version",
			Value: "24.1.0",
		},
	}

	tests := []struct {
		tag  string
		want string
	}{
		{
			tag:  "com.google.android.gms",
			want: "261233000",
		},
		{
			tag:  "com.google.firebase.auth",
			want: "24.1.0",
		},
		{
			tag:  "com.unknown.package",
			want: "",
		},
	}

	for _, tt := range tests {
		got := findVersionInMetadata(metadataEntries, tt.tag)
		if got != tt.want {
			t.Fatalf("findVersionInMetadata(%q) = %q, want %q",
				tt.tag, got, tt.want)
		}
	}
}

func TestResolveAttributionVersion(t *testing.T) {
	metadataEntries := []metaData{
		{
			Name:  "com.google.android.gms.version",
			Value: "261233000",
		},
	}

	got := resolveAttributionVersion(metadataEntries, "com.google.android.gms")
	want := "26.12.33"

	if got != want {
		t.Fatalf("resolveAttributionVersion() = %q, want %q", got, want)
	}
}

func TestCollectAllMetadata(t *testing.T) {
	manifest := &manifest{
		Application: application{
			MetaData: []metaData{
				{
					Name:  "app.meta",
					Value: "1",
				},
			},
			Activities: []activity{
				{
					MetaData: []metaData{
						{
							Name:  "activity.meta",
							Value: "2",
						},
					},
				},
			},
			Services: []service{
				{
					MetaData: []metaData{
						{
							Name:  "service.meta",
							Value: "3",
						},
					},
				},
			},
			Providers: []provider{
				{
					MetaData: []metaData{
						{
							Name:  "provider.meta",
							Value: "4",
						},
					},
				},
			},
		},
	}

	all := collectAllMetadata(manifest)

	if len(all) != 4 {
		t.Fatalf("collectAllMetadata() returned %d entries, want 4", len(all))
	}
}

func TestExtractInventoryFrommanifest(t *testing.T) {
	manifest := &manifest{
		Package: "com.google.android.gms",
		Attributions: []attribution{
			{
				Tag: "com.google.android.gms.ads",
			},
		},
		Application: application{
			MetaData: []metaData{
				{
					Name:  "com.google.android.gms.ads.version",
					Value: "261233000",
				},
			},
		},
	}

	pkgs := extractInventoryFromManifest(manifest, "/tmp/test.apk")

	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}

	pkg := pkgs[0]

	if pkg.Name != "com.google.android.gms.ads" {
		t.Fatalf("unexpected package name: %q", pkg.Name)
	}

	if pkg.Version != "26.12.33" {
		t.Fatalf("unexpected version: %q", pkg.Version)
	}

	md, ok := pkg.Metadata.(*metadata.Metadata)
	if !ok {
		t.Fatal("metadata type assertion failed")
	}

	if md.GroupID != "com.google.android.gms" {
		t.Fatalf("unexpected group id: %q", md.GroupID)
	}

	if md.ArtifactID != "play-services-ads" {
		t.Fatalf("unexpected artifact id: %q", md.ArtifactID)
	}
}
