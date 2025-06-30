package dpkgfilter

import (
	"bufio"
	"context"
	"errors"
	"io"
	"path"
	"strings"

	"github.com/google/osv-scalibr/annotator/ffa/unknownbinaries/internal/filter"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/fs/diriterate"
)

var (
	dpkgInfoDirPath  = "var/lib/dpkg/info"
	ignorePathPrefix = []string{
		"/var/lib/dpkg/info",
	}
)

type DpkgFilter struct{}

var _ filter.Filter = DpkgFilter{}

func (DpkgFilter) Name() string {
	return "DpkgFilter"
}

func (DpkgFilter) HashSetFilter(ctx context.Context, fs scalibrfs.FS, unknownBinariesSet map[string]struct{}) error {
	dirs, err := diriterate.ReadDir(fs, dpkgInfoDirPath)
	if err != nil {
		return err
	}
	defer dirs.Close()

	errs := []error{}
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

func (d DpkgFilter) ShouldExclude(ctx context.Context, fs scalibrfs.FS, binaryPath string) bool {
	for _, ignorePath := range ignorePathPrefix {
		if strings.HasPrefix(binaryPath, ignorePath) {
			return false
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
