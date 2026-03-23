package rpm

import (
	"compress/gzip"
	"database/sql"
	"encoding/xml"
	"errors"
	"io"
	iofs "io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	rpmdb "github.com/erikvarga/go-rpmdb/pkg"
	"github.com/google/osv-scalibr/fs"

	_ "modernc.org/sqlite" // Import sqlite driver
)

const (
	dnfRepoListDir    = "var/cache/dnf"
	zypperRepoListDir = "var/cache/zypp/raw"
	yumRepoListDir    = "var/cache/yum"
)

var (
	ErrMissingCache = errors.New("rpm cache is empty")
)

type mainOSPackages struct {
	value map[string]struct{}
}

func (m *mainOSPackages) Contains(pkg *rpmdb.PackageInfo) bool {
	p := rpmPackage{
		Name: pkg.Name,
		Arch: pkg.Arch,
		Version: rpmVersion{
			Epoch: pkg.Epoch,
			Ver:   pkg.Version,
			Rel:   pkg.Release,
		},
	}
	_, exists := m.value[p.Key()]
	return exists
}

type rpmPackage struct {
	Name    string     `xml:"name"`
	Arch    string     `xml:"arch"`
	Version rpmVersion `xml:"version"`
}
type rpmVersion struct {
	Epoch *int   `xml:"epoch,attr"`
	Ver   string `xml:"ver,attr"`
	Rel   string `xml:"rel,attr"`
}

func (p rpmPackage) Key() string {
	epoch := "0"
	if p.Version.Epoch != nil {
		epoch = strconv.Itoa(*p.Version.Epoch)
	}
	key := p.Name + "-" + epoch + ":" + p.Version.Ver + "-" + p.Version.Rel
	if p.Arch != "" {
		key += "." + p.Arch
	}
	return key
}

func extractMainRepos(root *fs.ScanRoot) (*mainOSPackages, error) {
	type extractor struct {
		indicators []string
		extract    func(*fs.ScanRoot) (*mainOSPackages, error)
	}

	// use config files as indicators to reliably detect the correct package manager
	// since cache folder may be removed
	extractors := []extractor{
		{indicators: []string{"etc/dnf/dnf.conf"}, extract: extractDnfMainRepos},
		{indicators: []string{"etc/zypp/zypp.conf"}, extract: extractZypperMainRepos},
		{indicators: []string{"etc/yum/yum.conf"}, extract: extractYumMainRepos},
	}

	for _, e := range extractors {
		if !hasPackageManager(root, e.indicators) {
			continue
		}
		return e.extract(root)
	}

	return nil, errors.New("package manager not supported")
}

func hasPackageManager(root *fs.ScanRoot, indicators []string) bool {
	for _, path := range indicators {
		if _, err := iofs.Stat(root.FS, path); err == nil {
			return true
		}
	}
	return false
}

func extractDnfMainRepos(root *fs.ScanRoot) (*mainOSPackages, error) {
	entries, err := iofs.ReadDir(root.FS, dnfRepoListDir)
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return nil, ErrMissingCache
		}
		return nil, err
	}

	if len(entries) == 0 {
		return nil, ErrMissingCache
	}

	cache := &mainOSPackages{
		value: make(map[string]struct{}),
	}

	mainOSRepos := []string{"appstream-", "baseos-", "codeready-builder-", "crb-"}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()

		isMainDnfRepo := slices.ContainsFunc(mainOSRepos, func(p string) bool { return strings.Contains(name, p) })
		if !isMainDnfRepo {
			continue
		}

		path := filepath.Join(dnfRepoListDir, name, "repodata")

		repoEntries, err := iofs.ReadDir(root.FS, path)
		if err != nil {
			return nil, err
		}

		for _, e := range repoEntries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), "primary.xml.gz") {
				filePath := filepath.Join(path, e.Name())
				// dnf use the same repository format as zypper
				if err := parseLibsolvRepo(root.FS, filePath, cache); err != nil {
					return nil, err
				}
			}
		}
	}

	return cache, nil
}

func extractZypperMainRepos(root *fs.ScanRoot) (*mainOSPackages, error) {
	entries, err := iofs.ReadDir(root.FS, zypperRepoListDir)
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return nil, ErrMissingCache
		}
		return nil, err
	}

	if len(entries) == 0 {
		return nil, ErrMissingCache
	}

	cache := &mainOSPackages{
		value: make(map[string]struct{}),
	}
	mainOSPrefixes := []string{"SLE_BCI", "packagehub", "repo-sle-update", "repo-update", "repo-backports-update"}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()

		isMainDnfRepo := slices.ContainsFunc(mainOSPrefixes, func(p string) bool { return strings.HasPrefix(name, p) })
		if !isMainDnfRepo {
			continue
		}

		path := filepath.Join(zypperRepoListDir, name, "repodata")

		repoEntries, err := iofs.ReadDir(root.FS, path)
		if err != nil {
			if errors.Is(err, iofs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		for _, e := range repoEntries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), "primary.xml.gz") {
				filePath := filepath.Join(path, e.Name())
				if err := parseLibsolvRepo(root.FS, filePath, cache); err != nil {
					return nil, err
				}
			}
		}
	}

	return cache, nil
}

func extractYumMainRepos(root *fs.ScanRoot) (*mainOSPackages, error) {
	entries, err := iofs.ReadDir(root.FS, yumRepoListDir)
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			return nil, ErrMissingCache
		}
		return nil, err
	}

	if len(entries) == 0 {
		return nil, ErrMissingCache
	}

	cache := &mainOSPackages{
		value: make(map[string]struct{}),
	}

	mainOSRepos := []string{"base", "updates", "extras", "centos", "rhel", "epel", "ol"}

	// YUM caches can be nested (e.g. /var/cache/yum/x86_64/7/base/repodata)
	// WalkDir allows us to find primary.xml.gz regardless of directory depth.
	err = iofs.WalkDir(root.FS, yumRepoListDir, func(path string, d iofs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), "primary.sqlite.gz") {
			return nil
		}

		// Extract the repository name from the path.
		// Path example: var/cache/yum/x86_64/7/base/primary.sqlite.gz
		parts := strings.Split(filepath.ToSlash(path), "/")

		// If standard structure, the repo name is 2 directories up from the file
		if len(parts) < 3 {
			return nil
		}
		repoName := parts[len(parts)-3]

		isMainDnfRepo := slices.ContainsFunc(mainOSRepos, func(p string) bool { return strings.Contains(repoName, p) })
		if !isMainDnfRepo {
			return nil
		}

		return parseYumRepo(root.FS, path, cache)
	})

	if err != nil {
		return nil, err
	}

	if len(cache.value) == 0 {
		return nil, ErrMissingCache
	}

	return cache, nil
}

// parseYumRepo decompresses a YUM primary.sqlite.gz file to disk and queries it.
func parseYumRepo(fsys fs.FS, path string, cache *mainOSPackages) error {
	file, err := fsys.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzReader.Close()

	// 1. Create a temporary file because database/sql requires a filepath
	tmpFile, err := os.CreateTemp("", "yum-primary-*.sqlite")
	if err != nil {
		return err
	}
	// Ensure the temp file is deleted when we're done
	defer os.Remove(tmpFile.Name())

	if _, err := io.Copy(tmpFile, gzReader); err != nil {
		tmpFile.Close()
		return err
	}
	tmpFile.Close()

	db, err := sql.Open("sqlite", tmpFile.Name())
	if err != nil {
		return err
	}
	defer db.Close()

	rows, err := db.Query("SELECT name, arch, epoch, version, release FROM packages")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		pkg := rpmPackage{}
		if err := rows.Scan(&pkg); err != nil {
			return err
		}
		cache.value[pkg.Key()] = struct{}{}
	}

	return rows.Err()
}

// parseLibsolvRepo parses repository information contained in primary.xml.gz files
//
// zypper and dnf share the same underlying cache implementation
func parseLibsolvRepo(fsys fs.FS, path string, cache *mainOSPackages) error {
	file, err := fsys.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzReader.Close()

	decoder := xml.NewDecoder(gzReader)
	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		switch se := token.(type) {
		case xml.StartElement:
			if se.Name.Local != "package" {
				continue
			}

			var pkg rpmPackage
			if err := decoder.DecodeElement(&pkg, &se); err != nil {
				return err
			}

			if pkg.Name != "" && pkg.Version.Ver != "" {
				cache.value[pkg.Key()] = struct{}{}
			}
		}
	}

	return nil
}
