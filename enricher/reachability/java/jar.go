// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package java

import (
	"archive/zip"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/osv-scalibr/extractor"
	archivemeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive/metadata"
	"github.com/google/osv-scalibr/log"
	"golang.org/x/sync/errgroup"
)

const (
	maxGoroutines = 4
	rootArtifact  = "<root>"
)

// MavenBaseURL is the base URL for the repository.
var MavenBaseURL = "https://repo1.maven.org/maven2"

var (
	// ErrClassNotFound is returned when a class is not found.
	ErrClassNotFound = errors.New("class not found")
	// ErrArtifactNotFound is returned when an artifact is not found.
	ErrArtifactNotFound = errors.New("artifact not found")
)

// MavenPackageFinder is an interface for finding Maven packages that contain a
// class path.
type MavenPackageFinder interface {
	// Find returns a list of package names that contain a class path.
	Find(classPath string) ([]string, error)
	// Find returns a list of class names that are part of a package.
	Classes(artifact string) ([]string, error)
}

// DefaultPackageFinder implements a MavenPackageFinder that downloads all .jar
// dependencies on demand and computes a local class to jar mapping.
type DefaultPackageFinder struct {
	// map of class to maven dependencies.
	classMap map[string][]string
	// map of maven dependency to class files.
	artifactMap map[string][]string
	// set of package coordinates (groupID:artifactID:version) whose JARs were successfully mapped.
	mappedPackages map[string]struct{}
}

func packageKey(pkg *extractor.Package) (string, bool) {
	if pkg == nil {
		return "", false
	}
	metadata, ok := pkg.Metadata.(*archivemeta.Metadata)
	if !ok || metadata == nil {
		return "", false
	}
	return metadata.GroupID + ":" + metadata.ArtifactID + ":" + pkg.Version, true
}

// loadJARMappings loads class mappings from a JAR archive.
func loadJARMappings(metadata *archivemeta.Metadata, pkgKey string, reader *zip.Reader, classMap map[string][]string, artifactMap map[string][]string, mappedPackages map[string]struct{}, lock *sync.Mutex) {
	lock.Lock()
	defer lock.Unlock()
	mappedPackages[pkgKey] = struct{}{}
	artifactName := metadata.GroupID + ":" + metadata.ArtifactID
	for _, f := range reader.File {
		if strings.HasSuffix(f.Name, ".class") {
			addClassMapping(artifactName, f.Name, classMap, artifactMap)
		}
	}
}

func addClassMapping(artifactName, class string, classMap map[string][]string, artifactMap map[string][]string) {
	name := strings.TrimSuffix(class, ".class")
	if after, ok := strings.CutPrefix(name, MetaInfVersions); ok {
		// Strip the version after the META-INF/versions/<version>/
		name = after[1:]
		name = name[strings.Index(name, "/")+1:]
	}

	classMap[name] = append(classMap[name], artifactName)
	artifactMap[artifactName] = append(artifactMap[artifactName], name)
	log.Debug("mapping", "name", name, "to", classMap[name])
}

// extractClassMappings extracts class mappings from a .jar dependency by
// downloading and unpacking the .jar from the relevant registry.
func extractClassMappings(ctx context.Context, inv *extractor.Package, classMap map[string][]string, artifactMap map[string][]string, mappedPackages map[string]struct{}, client *http.Client, lock *sync.Mutex) error {
	pkgKey, ok := packageKey(inv)
	if !ok {
		return errors.New("missing maven metadata for package")
	}
	metadata := inv.Metadata.(*archivemeta.Metadata)
	// TODO(#841): Handle when a class file contains in a nested JAR.

	// Try downloading the same package from Maven Central.
	jarURL := fmt.Sprintf("%s/%s/%s/%s/%s-%s.jar",
		MavenBaseURL,
		strings.ReplaceAll(metadata.GroupID, ".", "/"), metadata.ArtifactID, inv.Version, metadata.ArtifactID, inv.Version)
	file, err := os.CreateTemp("", "")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()

	log.Debug("downloading", "jar", jarURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jarURL, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return errors.New("jar not found: " + jarURL)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %q downloading jar %q", resp.Status, jarURL)
	}

	nbytes, err := io.Copy(file, resp.Body)
	if err != nil {
		return err
	}

	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	var reader *zip.Reader
	reader, err = zip.NewReader(file, nbytes)
	if err != nil {
		return err
	}

	loadJARMappings(metadata, pkgKey, reader, classMap, artifactMap, mappedPackages, lock)

	return nil
}

// NewDefaultPackageFinder creates a new DefaultPackageFinder based on a set of
// inventory.
func NewDefaultPackageFinder(ctx context.Context, inv []*extractor.Package, jarRoot *os.Root, client *http.Client) (*DefaultPackageFinder, error) {
	// Download pkg, unpack, and store class mappings for each detected dependency.
	classMap := map[string][]string{}
	artifactMap := map[string][]string{}
	mappedPackages := map[string]struct{}{}
	lock := new(sync.Mutex)
	group := new(errgroup.Group)
	group.SetLimit(maxGoroutines)

	errs := make([]error, len(inv))
	for idx, pkg := range inv {
		group.Go(func() error {
			dlErr := extractClassMappings(ctx, pkg, classMap, artifactMap, mappedPackages, client, lock)
			errs[idx] = dlErr
			return dlErr
		})
	}

	if group.Wait() != nil {
		var downloadErrs []error
		for _, dlErr := range errs {
			if dlErr != nil {
				downloadErrs = append(downloadErrs, dlErr)
				log.Debugf("Failed to download or map Maven package: %v", dlErr)
			}
		}

		if len(mappedPackages) == 0 {
			cause := downloadErrs[0]
			if ctx.Err() != nil {
				cause = ctx.Err()
			}
			allFailedErr := fmt.Errorf("failed to download all %d Maven packages (first error: %w)", len(downloadErrs), cause)
			log.Errorf("Java reachability enricher %v", allFailedErr)
			return nil, allFailedErr
		}
		// Tolerate partial errors (e.g. root application POM or private dependencies not on Maven Central);
		// unmapped packages will not receive a reachability verdict.
		log.Warnf("Java reachability enricher failed to download %d/%d Maven packages (first error: %v); skipping reachability verdict for unmapped packages",
			len(downloadErrs), len(inv), downloadErrs[0])
	}

	if err := mapRootClasses(jarRoot, classMap, artifactMap); err != nil {
		return nil, err
	}

	return &DefaultPackageFinder{
		classMap:       classMap,
		artifactMap:    artifactMap,
		mappedPackages: mappedPackages,
	}, nil
}

// mapRootClasses maps class files to the root application where we can determine that association.
func mapRootClasses(jarRoot *os.Root, classMap map[string][]string, artifactMap map[string][]string) error {
	// Spring Boot.
	// TODO(#787): Handle non-Spring Boot applications. We could add heuristic for
	// detecting root application classes when the class structure is flat based
	// on the class hierarchy.
	if _, err := jarRoot.Stat(BootInfClasses); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}

		return err
	}
	log.Debug("Found Spring Boot classes", "classes", BootInfClasses)

	return fs.WalkDir(jarRoot.FS(), BootInfClasses, func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".class") {
			name, err := filepath.Rel(BootInfClasses, path)
			if err != nil {
				return err
			}

			addClassMapping(rootArtifact, name, classMap, artifactMap)

			return nil
		}

		return nil
	})
}

// Find returns a list of package names that contain a class path.
func (f *DefaultPackageFinder) Find(classPath string) ([]string, error) {
	if pkg, ok := f.classMap[classPath]; ok {
		return pkg, nil
	}

	return nil, ErrClassNotFound
}

// Classes find returns a list of package names that contain a class path.
func (f *DefaultPackageFinder) Classes(artifact string) ([]string, error) {
	if classes, ok := f.artifactMap[artifact]; ok {
		return classes, nil
	}

	return nil, ErrArtifactNotFound
}

// IsMapped reports whether class mappings were successfully loaded for pkg.
func (f *DefaultPackageFinder) IsMapped(pkg *extractor.Package) bool {
	if f == nil {
		return false
	}
	key, ok := packageKey(pkg)
	if !ok {
		return false
	}
	_, exists := f.mappedPackages[key]
	return exists
}

// GetMainClasses extracts the main class name from the MANIFEST.MF file in a .jar.
func GetMainClasses(manifest io.Reader) ([]string, error) {
	// Extract the Main-Class specified in MANIFEST.MF:
	// https://docs.oracle.com/javase/tutorial/deployment/jar/appman.html
	const mainClass = "Main-Class:"
	// Spring Boot specific metadata.
	const startClass = "Start-Class:"
	markers := []string{mainClass, startClass}

	scanner := bufio.NewScanner(manifest)

	var classes []string
	var lines []string

	// Read all lines into memory for easier processing.
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	for i := range lines {
		line := strings.TrimSpace(lines[i])
		for _, marker := range markers {
			if strings.HasPrefix(line, marker) {
				var class strings.Builder

				class.WriteString(strings.TrimSpace(strings.TrimPrefix(line, marker)))

				// Handle wrapped lines. Class names exceeding line length limits
				// may be split across multiple lines, starting with a space.
				for index := i + 1; index < len(lines); index++ {
					nextLine := lines[index]
					if strings.HasPrefix(nextLine, " ") {
						class.WriteString(strings.TrimSpace(nextLine))
					} else {
						break
					}
				}
				classes = append(classes, strings.ReplaceAll(class.String(), ".", "/"))
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(classes) > 0 {
		return classes, nil
	}

	return nil, errors.New("no main class")
}
