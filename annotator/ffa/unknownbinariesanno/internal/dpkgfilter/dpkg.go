// Package dpkgfilter filters out binaries that are part of a dpkg package
package dpkgfilter

import (
	"bufio"
	"context"
	"errors"
	"io"
	"path"
	"strings"

	"github.com/google/osv-scalibr/annotator/ffa/unknownbinariesanno/internal/filter"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/fs/diriterate"
)

var (
	dpkgInfoDirPath = "var/lib/dpkg/info"

	ignorePathPrefix = []string{
		// We want to ignore everything in the info directory as DPKG indexes doesn't index itself.
		// There are many executable scripts in this directory, including preinstall/postinstall/preremove/postremove scripts.
		"var/lib/dpkg/info",
		// This is a debian docker specific file to disable irrelevant services from starting during apt install
		"usr/sbin/policy-rc.d",
	}
)

// DpkgFilter is a filter for binaries that are part of a dpkg package.
type DpkgFilter struct{}

var _ filter.Filter = DpkgFilter{}

// Name returns the name of the filter.
func (DpkgFilter) Name() string {
	return "DpkgFilter"
}

// HashSetFilter removes binaries from the input set that are found in dpkg .list files.
func (DpkgFilter) HashSetFilter(ctx context.Context, fs scalibrfs.FS, unknownBinariesSet map[string]struct{}) error {
	dirs, err := diriterate.ReadDir(fs, dpkgInfoDirPath)
	if err != nil {
		return err
	}
	defer dirs.Close()

	var errs []error
	for {
		// Return if canceled or exceeding deadline.
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}

		f, err := dirs.Next()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				errs = append(errs, err)
			}
			break
		}

		if !f.IsDir() && path.Ext(f.Name()) == ".list" {
			if err := processDpkgListFile(path.Join(dpkgInfoDirPath, f.Name()), fs, unknownBinariesSet); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}

// ShouldExclude returns whether a given binary path should be excluded from the scan.
func (d DpkgFilter) ShouldExclude(_ context.Context, _ scalibrfs.FS, binaryPath string) bool {
	for _, ignorePath := range ignorePathPrefix {
		if strings.HasPrefix(binaryPath, ignorePath) {
			return true
		}
	}

	return false
}

func processDpkgListFile(path string, fs scalibrfs.FS, knownBinariesSet map[string]struct{}) error {
	reader, err := fs.Open(path)
	if err != nil {
		return err
	}
	defer reader.Close()

	s := bufio.NewScanner(reader)
	for s.Scan() {
		// Remove leading '/' since SCALIBR fs paths don't include that.
		// noop if filePath doesn't exist
		delete(knownBinariesSet, strings.TrimPrefix(s.Text(), "/"))

		evalPath, err := fs.(image.EvalSymlinksFS).EvalSymlink(s.Text())
		if err != nil {
			continue
		}

		delete(knownBinariesSet, strings.TrimPrefix(evalPath, "/"))
	}
	return nil
}
