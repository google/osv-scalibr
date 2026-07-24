package androidapk

import (
	"os"
	"testing"
)

func TestLoadManifest_Metadata(t *testing.T) {
	root, err := os.OpenRoot("testdata")
	if err != nil {
		t.Fatalf("OpenRoot(testdata): %v", err)
	}
	defer root.Close()

	// manifest will hold normalized AndroidManifest.xml.
	manifest, normalizedManifest, err := loadManifest(root)
	if err != nil {
		t.Fatalf("manifest processing failed: %v", err)
	}

	if manifest == nil {
		t.Fatal("manifest is nil")
	}

	if normalizedManifest == nil {
		t.Fatal("normalized manifest bytes are nil")
	}

	// Verify package name exists
	if manifest.Package == "" {
		t.Error("expected package name to be populated")
	}

	// Verify application metadata can be read
	for _, md := range manifest.Application.MetaData {
		t.Logf("Application MetaData: name=%q value=%q", md.Name, md.Value)
	}

	// Verify activity metadata can be read
	for _, activity := range manifest.Application.Activities {
		for _, md := range activity.MetaData {
			t.Logf("Activity MetaData: name=%q value=%q", md.Name, md.Value)
		}
	}

	// Verify service metadata can be read
	for _, service := range manifest.Application.Services {
		for _, md := range service.MetaData {
			t.Logf("Service MetaData: name=%q value=%q", md.Name, md.Value)
		}
	}

	// Verify provider metadata can be read
	for _, provider := range manifest.Application.Providers {
		for _, md := range provider.MetaData {
			t.Logf("Provider MetaData: name=%q value=%q", md.Name, md.Value)
		}
	}
}

func TestDumpManifest(t *testing.T) {
	tempDir := t.TempDir()

	root, err := os.OpenRoot(tempDir)
	if err != nil {
		t.Fatalf("OpenRoot(%q): %v", tempDir, err)
	}
	defer root.Close()

	manifestData := []byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest package="com.example.app">
    <application />
</manifest>`)

	if err := dumpManifest(manifestData, root); err != nil {
		t.Fatalf("DumpManifest() returned error: %v", err)
	}

	// Verify file exists
	info, err := root.Stat("AndroidManifest.normalized.xml")
	if err != nil {
		t.Fatalf("expected manifest file to exist: %v", err)
	}

	if info.IsDir() {
		t.Fatal("expected manifest output to be a file, got directory")
	}

	// Verify contents
	got, err := root.ReadFile("AndroidManifest.normalized.xml")
	if err != nil {
		t.Fatalf("failed to read dumped manifest: %v", err)
	}

	if string(got) != string(manifestData) {
		t.Errorf("manifest contents mismatch\nGot:\n%s\nWant:\n%s", got, manifestData)
	}
}

func TestDumpManifest_EmptyManifest(t *testing.T) {
	tempDir := t.TempDir()

	root, err := os.OpenRoot(tempDir)
	if err != nil {
		t.Fatalf("OpenRoot(%q): %v", tempDir, err)
	}
	defer root.Close()

	if err := dumpManifest(nil, root); err == nil {
		t.Fatal("expected error for empty manifest, got nil")
	}
}
