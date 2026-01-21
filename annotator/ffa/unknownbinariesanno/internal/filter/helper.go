package filter

import (
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/ffa/unknownbinariesextr"
)

// AttributePackage marks a package found in unknownBinariesSet as belonging to the local filesystem
// by adding attribution in the package's metadata
func AttributePackage(unknownBinariesSet map[string]*extractor.Package, path string) {
	pkg, ok := unknownBinariesSet[strings.TrimPrefix(path, "/")]
	if !ok {
		return
	}

	md, ok := pkg.Metadata.(*unknownbinariesextr.UnknownBinaryMetadata)
	if !ok {
		return
	}

	md.Attribution.LocalFilesystem = true
}
