package androidapk

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseManifest_Metadata(t *testing.T) {
	manifestPath := filepath.Join("testdata", "AndroidManifest.xml")

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read manifest file: %v", err)
	}

	manifest, err := ParseManifest(data)
	if err != nil {
		t.Fatalf("failed to parse manifest: %v", err)
	}

	if manifest == nil {
		t.Fatal("manifest is nil")
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

	manifestData := []byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest package="com.example.app">
    <application />
</manifest>`)

	err := DumpManifest(manifestData, tempDir)
	if err != nil {
		t.Fatalf("DumpManifest() returned error: %v", err)
	}

	outputPath := filepath.Join(tempDir, "AndroidManifestNormalized.xml")

	// Verify file exists
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("expected manifest file to exist: %v", err)
	}

	if info.IsDir() {
		t.Fatal("expected manifest output to be a file, got directory")
	}

	// Verify contents
	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read dumped manifest: %v", err)
	}

	if string(got) != string(manifestData) {
		t.Errorf("manifest contents mismatch\nGot:\n%s\nWant:\n%s", got, manifestData)
	}
}

func TestDumpManifest_EmptyManifest(t *testing.T) {
	tempDir := t.TempDir()

	err := DumpManifest(nil, tempDir)
	if err == nil {
		t.Fatal("expected error for empty manifest, got nil")
	}
}
