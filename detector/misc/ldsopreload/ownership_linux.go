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

//go:build linux

package ldsopreload

import (
	"errors"
	"fmt"
	"io/fs"
	"syscall"
)

var errOwnershipUnavailable = errors.New("ownership info unavailable")

func ownershipIssues(subject string, info fs.FileInfo) ([]string, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("%s: %w", subject, errOwnershipUnavailable)
	}

	issues := []string{}
	if stat.Uid != 0 {
		issues = append(issues, fmt.Sprintf(
			"%s is not owned by root (uid: %d)", subject, stat.Uid))
	}
	if stat.Gid != 0 {
		issues = append(issues, fmt.Sprintf(
			"%s is not group-owned by root (gid: %d)", subject, stat.Gid))
	}

	return issues, nil
}
