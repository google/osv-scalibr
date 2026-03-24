package tempdir_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/tempdir"
)

func TestRootCreation(t *testing.T) {
	root, err := tempdir.Root()
	if err != nil {
		t.Fatalf("Root() returned error: %v", err)
	}

	if root == "" {
		t.Fatal("Root() returned empty path")
	}

	info, err := os.Stat(root)
	if err != nil {
		t.Fatalf("Root directory does not exist: %v", err)
	}

	if !info.IsDir() {
		t.Fatalf("Root path is not a directory")
	}
}

func TestRootIsSingleton(t *testing.T) {
	root1, _ := tempdir.Root()
	root2, _ := tempdir.Root()

	if root1 != root2 {
		t.Fatalf("Expected same root directory, got %s and %s", root1, root2)
	}
}

func TestCreateDir(t *testing.T) {
	dir, err := tempdir.CreateDir("testdir")
	if err != nil {
		t.Fatalf("CreateDir() failed: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Directory does not exist: %v", err)
	}

	if !info.IsDir() {
		t.Fatalf("Path is not a directory")
	}
}

func TestCreateNestedDir(t *testing.T) {
	dir, err := tempdir.CreateDir("nested/testdir")
	if err != nil {
		t.Fatalf("CreateDir() failed: %v", err)
	}

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("Nested directory not created: %v", err)
	}
}

func TestCreateExtractorDir(t *testing.T) {
	plugin := "qcow2"
	filename := "/tmp/test.img"

	dir, err := tempdir.CreateExtractorDir(plugin, filename)
	if err != nil {
		t.Fatalf("CreateExtractorDir() failed: %v", err)
	}

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("Directory not created: %v", err)
	}

	root, _ := tempdir.Root()

	expectedSuffix := filepath.Join("extractor", plugin, filepath.Base(filename))
	if !strings.HasSuffix(dir, expectedSuffix) {
		t.Fatalf("Unexpected directory structure: got %s", dir)
	}

	if !strings.HasPrefix(dir, root) {
		t.Fatalf("Directory created outside root")
	}
}

func TestCreateEnricherDir(t *testing.T) {
	plugin := "osv"
	filename := "package.json"

	dir, err := tempdir.CreateEnricherDir(plugin, filename)
	if err != nil {
		t.Fatalf("CreateEnricherDir() failed: %v", err)
	}

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("Directory not created: %v", err)
	}

	root, _ := tempdir.Root()

	expectedSuffix := filepath.Join("enricher", plugin, filepath.Base(filename))
	if !strings.HasSuffix(dir, expectedSuffix) {
		t.Fatalf("Unexpected directory structure: got %s", dir)
	}

	if !strings.HasPrefix(dir, root) {
		t.Fatalf("Directory created outside root")
	}
}

func TestCreateDetectorDir(t *testing.T) {
	plugin := "secrets"
	filename := "dump.txt"

	dir, err := tempdir.CreateDetectorDir(plugin, filename)
	if err != nil {
		t.Fatalf("CreateDetectorDir() failed: %v", err)
	}

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("Directory not created: %v", err)
	}

	root, _ := tempdir.Root()

	expectedSuffix := filepath.Join("detector", plugin, filepath.Base(filename))
	if !strings.HasSuffix(dir, expectedSuffix) {
		t.Fatalf("Unexpected directory structure: got %s", dir)
	}

	if !strings.HasPrefix(dir, root) {
		t.Fatalf("Directory created outside root")
	}
}

func TestCreateFile_DefaultRoot(t *testing.T) {
	path, file, err := tempdir.CreateFile("", "test-*.txt")
	if err != nil {
		t.Fatalf("CreateFile() failed: %v", err)
	}
	defer file.Close()

	if path == "" {
		t.Fatalf("Empty file path returned")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Temp file does not exist: %v", err)
	}

	if info.IsDir() {
		t.Fatalf("Expected file, got directory")
	}

	root, _ := tempdir.Root()
	if filepath.Dir(path) != root {
		t.Fatalf("File not created under root directory")
	}
}

func TestCreateFile_InSubDir(t *testing.T) {
	dir := "subdir1/subdir2"

	path, file, err := tempdir.CreateFile(dir, "nested-*.log")
	if err != nil {
		t.Fatalf("CreateFile() failed: %v", err)
	}
	defer file.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Temp file does not exist: %v", err)
	}

	if info.IsDir() {
		t.Fatalf("Expected file, got directory")
	}

	root, _ := tempdir.Root()
	if !strings.HasPrefix(path, root) {
		t.Fatalf("File created outside root directory")
	}
}

func TestRemoveAll(t *testing.T) {
	name := "cleanup_test"

	dir, err := tempdir.CreateDir(name)
	if err != nil {
		t.Fatalf("CreateDir() failed: %v", err)
	}

	err = tempdir.RemoveAll(name)
	if err != nil {
		t.Fatalf("RemoveAll() failed: %v", err)
	}

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("Directory still exists after removal")
	}
}

func TestRemoveRoot(t *testing.T) {
	dir, err := tempdir.CreateDir("root_cleanup_test")
	if err != nil {
		t.Fatalf("CreateDir() failed: %v", err)
	}

	root := filepath.Dir(dir)

	err = tempdir.RemoveRoot()
	if err != nil {
		t.Fatalf("RemoveRoot() failed: %v", err)
	}

	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("Root directory still exists after cleanup")
	}
}

func TestDebugModePreventsCleanup(t *testing.T) {
	tempdir.SetDebug(true)

	dir, err := tempdir.CreateDir("debug_test")
	if err != nil {
		t.Fatalf("CreateDir() failed: %v", err)
	}

	root := filepath.Dir(dir)

	err = tempdir.RemoveRoot()
	if err != nil {
		t.Fatalf("RemoveRoot() returned error: %v", err)
	}

	if _, err := os.Stat(root); err != nil {
		t.Fatalf("Root directory removed in debug mode")
	}

	// manual cleanup
	os.RemoveAll(root)

	tempdir.SetDebug(false)
}

func TestPathTraversalPrevention(t *testing.T) {
	_, err := tempdir.CreateDir("../escape")
	if err == nil {
		t.Fatalf("Expected error for path traversal, got nil")
	}
}
