// Copyright 2025 Google LLC
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

package stats

import (
	"time"

	"github.com/google/osv-scalibr/inventory"
)

// AfterExtractorStats is a struct containing stats about the results of a file extraction run.
type AfterExtractorStats struct {
	Path    string
	Root    string
	Runtime time.Duration

	Inventory *inventory.Inventory
	Error     error
}

// FileRequiredStats is a struct containing stats about a file that was
// required or skipped by a plugin.
type FileRequiredStats struct {
	Path          string
	Result        FileRequiredResult
	FileSizeBytes int64
}

// FileRequiredResult is a string representation of the result of a call to
// `Extractor.FileRequired`.
type FileRequiredResult string

const (
	// FileRequiredResultOK indicates that the file was required by the plugin.
	FileRequiredResultOK FileRequiredResult = "FILE_REQUIRED_RESULT_OK"

	// FileRequiredResultSizeLimitExceeded indicates that the file was skipped
	// because it was too large.
	FileRequiredResultSizeLimitExceeded FileRequiredResult = "FILE_REQUIRED_RESULT_SIZE_LIMIT_EXCEEDED"
)

// FileExtractedStats is a struct containing stats about a file that was extracted. If
// the file was skipped due to an error during extraction, `Error` will be
// populated.
type FileExtractedStats struct {
	Path          string
	Result        FileExtractedResult
	FileSizeBytes int64

	// Optional. For extractors that unarchive a compressed files, this reports
	// the bytes that were opened during the unarchiving process.
	UncompressedBytes int64
}

// FileExtractedResult is a string representation of the result of a call to
// `Extractor.Extract`.
type FileExtractedResult string

const (
	// FileExtractedResultSuccess indicates that the file was extracted
	// successfully.
	FileExtractedResultSuccess FileExtractedResult = "FILE_EXTRACTED_RESULT_SUCCESS"

	// FileExtractedResultErrorUnknown indicates that an unknown error occurred
	// during extraction.
	FileExtractedResultErrorUnknown FileExtractedResult = "FILE_EXTRACTED_RESULT_ERROR_UNKNOWN"

	// FileExtractedResultErrorMemoryLimitExceeded indicates that the extraction
	// failed because the memory limit inside the plugin was exceeded.
	FileExtractedResultErrorMemoryLimitExceeded = "FILE_EXTRACTED_RESULT_ERROR_MEMORY_LIMIT_EXCEEDED"
)
