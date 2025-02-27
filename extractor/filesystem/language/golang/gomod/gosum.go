package gomod

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
)

// extractFromSum extracts dependencies from the go.sum file.
//
// Below 1.17 go.mod does not contain indirect dependencies
// but they might be in go.sum, thus we look into it as well.
//
// Note: This function may produce false positives, as the go.sum file might be outdated.
func extractFromSum(input *filesystem.ScanInput) (map[ivKey]*extractor.Inventory, error) {
	goSumPath := strings.TrimSuffix(input.Path, ".mod") + ".sum"
	f, err := input.FS.Open(goSumPath)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(f)
	packages := map[ivKey]*extractor.Inventory{}

	for lineNumber := 0; scanner.Scan(); lineNumber++ {
		line := scanner.Text()

		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 3 {
			return nil, fmt.Errorf("Error reading line: %d", lineNumber)
		}

		name := parts[0]
		version := strings.TrimPrefix(parts[1], "v")

		// skip a line if the version contains "/go.mod" because lines
		// containing "/go.mod" are duplicates used to verify the hash of the go.mod file
		if strings.Contains(version, "/go.mod") {
			continue
		}

		packages[ivKey{name: name, version: version}] = &extractor.Inventory{
			Name:      name,
			Version:   version,
			Locations: []string{goSumPath},
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return packages, nil
}
