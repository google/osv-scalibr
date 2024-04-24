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

package internal

import (
	"syscall"

	"github.com/google/osv-scalibr/log"
)

// MaxResident returns the max resident memory. This can be bytes or kilobytes, depending on the
// operating system.
func MaxResident() int64 {
	var u syscall.Rusage
	err := syscall.Getrusage(syscall.RUSAGE_SELF, &u)
	if err != nil {
		log.Warnf("Failed to get rusage: %v", err)
		return 0
	}

	return u.Maxrss
}
