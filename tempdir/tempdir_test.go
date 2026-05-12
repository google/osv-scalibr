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

	info, err := os.Stat(root.Name())
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
	name := "testdir"
	root, err := tempdir.CreateDir(name)
	if err != nil {
		t.Fatalf("CreateDir() failed: %v", err)
	}
	defer root.Close()

	if root == nil || root.Name() == "" {
		t.Fatal("CreateDir returned root with empty Name")
	}

	info, err := os.Stat(root.Name())
	if err != nil {
		t.Fatalf("Directory does not exist: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("Path is not a directory")
	}
}

func TestCreateNestedDir(t *testing.T) {
	name := "nested/testdir"
	root, err := tempdir.CreateDir(name)
	if err != nil {
		t.Fatalf("CreateDir() failed: %v", err)
	}
	defer root.Close()

	if _, err := os.Stat(root.Name()); err != nil {
		t.Fatalf("Nested directory not created: %v", err)
	}
}

func TestCreatePluginDir(t *testing.T) {
	pluginType := tempdir.Extractor
	plugin := "qcow2"
	filename := "test.img"

	root, err := tempdir.CreatePluginDir(pluginType, plugin, filename)
	if err != nil {
		t.Fatalf("CreatePluginDir() failed: %v", err)
	}
	defer root.Close()

	if _, err := os.Stat(root.Name()); err != nil {
		t.Fatalf("Directory not created: %v", err)
	}

	expectedSuffix := filepath.Join(string(pluginType), plugin, filepath.Base(filename))
	if !strings.HasSuffix(root.Name(), expectedSuffix) {
		t.Fatalf("Unexpected directory structure: got %s, expected suffix %s", root.Name(), expectedSuffix)
	}

	t.Logf("Root.Name() is: %q", root.Name())
}

func TestCreateFile_DefaultRoot(t *testing.T) {
	path, file, err := tempdir.CreateFile(nil, "test-*.txt")
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
	subRoot, err := tempdir.CreateDir(dir)
	if err != nil {
		t.Fatalf("CreateDir() failed: %v", err)
	}
	defer subRoot.Close()

	path, file, err := tempdir.CreateFile(subRoot, "nested-*.log")
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

func TestStat(t *testing.T) {
	name := "stat_test"
	root, err := tempdir.CreateDir(name)
	if err != nil {
		t.Fatalf("CreateDir failed: %v", err)
	}
	defer root.Close()

	info, err := tempdir.Stat(name)
	if err != nil {
		t.Fatalf("Stat() failed: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("Expected directory from Stat()")
	}
}

func TestRemoveAll(t *testing.T) {
	name := "cleanup_test"
	root, err := tempdir.CreateDir(name)
	if err != nil {
		t.Fatalf("CreateDir failed: %v", err)
	}
	root.Close()

	err = tempdir.RemoveAll(name)
	if err != nil {
		t.Fatalf("RemoveAll() failed: %v", err)
	}

	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Fatalf("Directory still exists after removal")
	}
}

func TestRemoveRoot(t *testing.T) {
	root, err := tempdir.CreateDir("root_cleanup_test")
	if err != nil {
		t.Fatalf("CreateDir failed: %v", err)
	}
	root.Close()

	path, err := tempdir.GetRootPath()
	if err != nil {
		t.Fatalf("GetRootPath failed: %v", err)
	}

	err = tempdir.RemoveRoot()
	if err != nil {
		t.Fatalf("RemoveRoot() failed: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("Root directory still exists after cleanup")
	}
}

func TestDiskLayout(t *testing.T) {
	// Get the scalibr root path for current run.
	rootPath, err := tempdir.GetRootPath()
	if err != nil {
		t.Fatalf("failed to get scalibr rootPath")
	}

	pluginType := tempdir.Extractor
	plugin := "qcow2"
	filename := "test.img"

	pluginRoot, err := tempdir.CreatePluginDir(pluginType, plugin, filename)
	if err != nil {
		t.Fatalf("CreatePluginDir() failed: %v", err)
	}
	defer pluginRoot.Close()

	// Create a file inside pluginRoot
	rawPath, _, err := tempdir.CreateFile(pluginRoot, "qcow2-*.raw")
	if err != nil {
		t.Fatalf("CreateFile() failed: %v", err)
	}

	// Create a partition subdir inside pluginRoot
	partitionSubDir := "partition-1-ext4"
	partitionRoot, err := tempdir.CreateSubDir(pluginRoot, partitionSubDir)
	if err != nil {
		t.Fatalf("CreateSubDir() failed: %v", err)
	}
	defer partitionRoot.Close()

	// Verify disk layout using os.Stat on absolute paths
	if _, err := os.Stat(rawPath); err != nil {
		t.Fatalf("Raw image file not created at expected path %s: %v", rawPath, err)
	}

	expectedPartitionPath := filepath.Join(rootPath, string(pluginType), plugin, filepath.Base(filename), partitionSubDir)
	if _, err := os.Stat(expectedPartitionPath); err != nil {
		t.Fatalf("Partition directory not created at expected path %s: %v", expectedPartitionPath, err)
	}
}
