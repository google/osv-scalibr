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

// Package osrelease parses the os-release file. More details in `man os-release 5`.
package osrelease

import (
	"bufio"
	"io"
	"os"
	"strings"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

// GetOSRelease tries different os-release locations and parses the first found.
func GetOSRelease(fs scalibrfs.FS) (map[string]string, error) {
	paths := []string{"etc/os-release", "usr/lib/os-release"}

	for _, p := range paths {
		f, err := fs.Open(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		defer f.Close()
		return parse(f), nil
	}

	return nil, os.ErrNotExist
}

// parse the os-release(5) file.
func parse(r io.Reader) map[string]string {
	s := bufio.NewScanner(r)

	m := map[string]string{}
	for s.Scan() {
		line := strings.TrimSpace(s.Text())

		if !strings.Contains(line, "=") || strings.HasPrefix(line, "#") {
			continue
		}

		kv := strings.SplitN(line, "=", 2)
		m[kv[0]] = resolveString(kv[1])
	}
	return m
}

// resolveString parses the right side of an environment-like shell-compatible variable assignment.
// Currently it just removes double quotes. See `man os-release 5` for more details.
func resolveString(s string) string {
	if strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") {
		s = s[1 : len(s)-1]
	}
	return s
}
