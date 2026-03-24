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
	if root == nil {
		t.Fatal("Root() returned nil")
	}

	info, err := os.Stat(rootPathHelper(t))
	if err != nil {
		t.Fatalf("Root directory does not exist: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("Root path is not a directory")
	}
}

func TestRootIsSingleton(t *testing.T) {
	root1, err1 := tempdir.Root()
	root2, err2 := tempdir.Root()
	if err1 != nil || err2 != nil {
		t.Fatalf("Root() failed: %v, %v", err1, err2)
	}
	if root1 != root2 {
		t.Fatal("Expected same *os.Root instance")
	}
}

func TestCreateDir(t *testing.T) {
	// Get the scalibr root path for current run.
	rootPath, err := tempdir.GetRootPath()
	if err != nil {
		t.Fatalf("failed to get scalibr rootPath")
	}

	name := "testdir"
	path, root, err := tempdir.CreateDir(name)
	if err != nil {
		t.Fatalf("CreateDir() failed: %v", err)
	}
	defer root.Close()

	if path == "" {
		t.Fatal("CreateDir returned empty path")
	}

	info, err := os.Stat(filepath.Join(rootPath, path))
	if err != nil {
		t.Fatalf("Directory does not exist: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("Path is not a directory")
	}
}

func TestCreateNestedDir(t *testing.T) {
	name := "nested/testdir"
	_, root, err := tempdir.CreateDir(name)
	if err != nil {
		t.Fatalf("CreateDir() failed: %v", err)
	}
	defer root.Close()

	if _, err := os.Stat(filepath.Join(rootPathHelper(t), name)); err != nil {
		t.Fatalf("Nested directory not created: %v", err)
	}
}

func TestCreateExtractorDir(t *testing.T) {
	plugin := "qcow2"
	filename := "test.img"

	path, root, err := tempdir.CreateExtractorDir(plugin, filename)
	if err != nil {
		t.Fatalf("CreateExtractorDir() failed: %v", err)
	}
	defer root.Close()

	if _, err := os.Stat(filepath.Join(rootPathHelper(t), path)); err != nil {
		t.Fatalf("Directory not created: %v", err)
	}

	expectedSuffix := filepath.Join("extractor", plugin, filepath.Base(filename))
	if !strings.HasSuffix(path, expectedSuffix) {
		t.Fatalf("Unexpected directory structure: got %s, expected suffix %s", path, expectedSuffix)
	}
}

func TestCreateEnricherDir(t *testing.T) {
	plugin := "osv"
	filename := "package.json"

	path, root, err := tempdir.CreateEnricherDir(plugin, filename)
	if err != nil {
		t.Fatalf("CreateEnricherDir() failed: %v", err)
	}
	defer root.Close()

	if _, err := os.Stat(filepath.Join(rootPathHelper(t), path)); err != nil {
		t.Fatalf("Directory not created: %v", err)
	}
}

func TestCreateDetectorDir(t *testing.T) {
	plugin := "secrets"
	filename := "dump.txt"

	path, root, err := tempdir.CreateDetectorDir(plugin, filename)
	if err != nil {
		t.Fatalf("CreateDetectorDir() failed: %v", err)
	}
	defer root.Close()

	if _, err := os.Stat(filepath.Join(rootPathHelper(t), path)); err != nil {
		t.Fatalf("Directory not created: %v", err)
	}
}

func TestCreateFile_DefaultRoot(t *testing.T) {
	path, file, err := tempdir.CreateFile("", "test-*.txt")
	if err != nil {
		t.Fatalf("CreateFile() failed: %v", err)
	}
	defer file.Close()

	if path == "" {
		t.Fatal("Empty file path returned")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Temp file does not exist: %v", err)
	}
	if info.IsDir() {
		t.Fatal("Expected file, got directory")
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
		t.Fatal("Expected file, got directory")
	}
}

func TestRemoveAll(t *testing.T) {
	name := "cleanup_test"
	_, root, err := tempdir.CreateDir(name)
	if err != nil {
		t.Fatalf("CreateDir failed: %v", err)
	}
	root.Close()

	err = tempdir.RemoveAll(name)
	if err != nil {
		t.Fatalf("RemoveAll() failed: %v", err)
	}

	fullPath := filepath.Join(rootPathHelper(t), name)
	if _, err := os.Stat(fullPath); !os.IsNotExist(err) {
		t.Fatalf("Directory still exists after removal")
	}
}

func TestRemoveRoot(t *testing.T) {
	_, root, err := tempdir.CreateDir("root_cleanup_test")
	if err != nil {
		t.Fatalf("CreateDir failed: %v", err)
	}
	root.Close()

	err = tempdir.RemoveRoot()
	if err != nil {
		t.Fatalf("RemoveRoot() failed: %v", err)
	}

	if _, err := os.Stat(rootPathHelper(t)); !os.IsNotExist(err) {
		t.Fatalf("Root directory still exists after cleanup")
	}
}

// Helper to get root path safely
func rootPathHelper(t *testing.T) string {
	t.Helper()
	path, err := tempdir.GetRootPath()
	if err != nil {
		t.Fatalf("GetRootPath failed: %v", err)
	}
	return path
}
