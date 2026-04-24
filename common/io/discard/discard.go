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

// Package discard contains logic to handle large input files
package discard

import (
	"bufio"
	"slices"
)

// LongLines returns a bufio.SplitFunc that discards lines exceeding maxLineSize.
func LongLines(maxLineSize int) bufio.SplitFunc {
	isSkipping := false

	return func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if isSkipping {
			if crIdx := slices.Index(data, '\n'); crIdx != -1 {
				// if newline is found stop skipping
				isSkipping = false
				return crIdx + 1, nil, nil
			}
			// keep skipping
			return len(data), nil, nil
		}

		advance, token, err = bufio.ScanLines(data, atEOF)

		// If buffer is full and no newline was found, trigger skip mode
		if advance == 0 && token == nil && err == nil && len(data) >= maxLineSize {
			isSkipping = true
			return len(data), nil, nil
		}

		return advance, token, err
	}
}
