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

package testcollector_test

import (
	"testing"

	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/testcollector"
)

func TestCollector(t *testing.T) {
	tests := []struct {
		name               string
		fileRequiredStats  *stats.FileRequiredStats
		fileExtractedStats *stats.FileExtractedStats
	}{
		{
			name: "file required stats",
			fileRequiredStats: &stats.FileRequiredStats{
				Path:          "testdata/required.txt",
				Result:        stats.FileRequiredResultOK,
				FileSizeBytes: 1000,
			},
		},
		{
			name: "file extracted stats",
			fileExtractedStats: &stats.FileExtractedStats{
				Path:              "testdata/extracted.txt",
				Result:            stats.FileExtractedResultSuccess,
				FileSizeBytes:     1000,
				UncompressedBytes: 2000,
			},
		},
		{
			name: "both file required and extracted stats",
			fileRequiredStats: &stats.FileRequiredStats{
				Path:          "testdata/required.txt",
				Result:        stats.FileRequiredResultSizeLimitExceeded,
				FileSizeBytes: 1000000,
			},
			fileExtractedStats: &stats.FileExtractedStats{
				Path:              "testdata/extracted.txt",
				Result:            stats.FileExtractedResultErrorMemoryLimitExceeded,
				FileSizeBytes:     1000,
				UncompressedBytes: 2000000,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			if tt.fileRequiredStats != nil {
				collector.AfterFileRequired("test", tt.fileRequiredStats)
			}
			if tt.fileExtractedStats != nil {
				collector.AfterFileExtracted("test", tt.fileExtractedStats)
			}

			if tt.fileRequiredStats != nil {
				gotResult := collector.FileRequiredResult(tt.fileRequiredStats.Path)
				if gotResult != tt.fileRequiredStats.Result {
					t.Errorf("FileRequiredResult(%s) = %v, want %v", tt.fileRequiredStats.Path, gotResult, tt.fileRequiredStats.Result)
				}
			}

			if tt.fileExtractedStats != nil {
				gotResult := collector.FileExtractedResult(tt.fileExtractedStats.Path)
				if gotResult != tt.fileExtractedStats.Result {
					t.Errorf("FileExtractedResult(%s) = %v, want %v", tt.fileExtractedStats.Path, gotResult, tt.fileExtractedStats.Result)
				}

				gotFileSize := collector.FileExtractedFileSize(tt.fileExtractedStats.Path)
				if gotFileSize != tt.fileExtractedStats.FileSizeBytes {
					t.Errorf("FileExtractedFileSize(%s) = %v, want %v", tt.fileExtractedStats.Path, gotFileSize, tt.fileExtractedStats.FileSizeBytes)
				}
			}
		})
	}
}
