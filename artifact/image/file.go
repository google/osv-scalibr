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

package image

import "io/fs"

// History holds the creation, modification, and deletion history of a file or inventory. Each field
// holds an array of integers representing layer indices.
type History struct {
	Created []int
	Edited  []int
	Deleted []int
}

// File is a file in a container image that can be scanned for software inventory. It also
// holds metadata about the file such as its permissions, type and the real file path.
type File interface {
	fs.File
	RealFilePath() string
}
