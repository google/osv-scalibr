// Copyright 2024 Google LLC
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

package extractor

import "errors"

var (
	// ErrExtractorMemoryLimitExceeded is returned when an extractor skips a file
	// due to the extraction process exceeding a configured memory limit.
	ErrExtractorMemoryLimitExceeded = errors.New("extraction failed due to extractor exceeding the configured memory limit")
)
