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

// Package etcshadow implements a detector for weak/guessable passwords stored in /etc/shadow.
package etcshadow

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"

	"github.com/google/osv-scalibr/detector"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the detector.
	Name = "weakcredentials/etcshadow"
)

// Detector is a SCALIBR Detector for weak/guessable passwords from /etc/shadow.
type Detector struct{}

// New returns a detector.
func New() detector.Detector {
	return &Detector{}
}

// Name of the detector.
func (Detector) Name() string { return Name }

// Version of the detector.
func (Detector) Version() int { return 0 }

// Requirements of the detector.
func (Detector) Requirements() *plugin.Capabilities { return &plugin.Capabilities{OS: plugin.OSUnix} }

// RequiredExtractors returns an empty list as there are no dependencies.
func (Detector) RequiredExtractors() []string { return []string{} }

// Scan starts the scan.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) ([]*detector.Finding, error) {
	f, err := scanRoot.FS.Open("etc/shadow")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// File doesn't exist, check not applicable.
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	users, err := parseShadowFile(f)
	if err != nil {
		return nil, err
	}

	cracker := NewPasswordCracker()

	// When looking at password hashes we strictly focus on hash strings
	// with the format $ALGO$SALT$HASH. There are many other things we choose
	// not to check for the sake of simplicity (e.g. hash strings preceded
	// by one or two ! characters are for locked logins - password can still be weak
	// and running as user can be done locally with the 'su' command).
	var problemUsers []string
	for user, hash := range users {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if _, err := cracker.Crack(ctx, hash); err == nil { // if cracked
			// Report only user name to avoid PII leakage.
			problemUsers = append(problemUsers, user)
		}
	}

	if len(problemUsers) == 0 {
		return nil, nil
	}

	title := "Ensure all users have strong passwords configured"
	description := "The /etc/shadow file contains user account password hashes. " +
		"These passwords must be strong and not easily guessable."
	recommendation := "Run the following command to reset password for the reported users:\n" +
		"# change password for USER: sudo passwd USER"

	// Sort users to avoid non-determinism in the processing order from users map.
	sort.Strings(problemUsers)
	buf := new(strings.Builder)
	_, _ = fmt.Fprintln(buf, "The following users have weak passwords:")
	for _, u := range problemUsers {
		_, _ = fmt.Fprintln(buf, u)
	}
	problemDescription := buf.String()

	return []*detector.Finding{{
		Adv: &detector.Advisory{
			ID: &detector.AdvisoryID{
				Publisher: "SCALIBR",
				Reference: "etc-shadow-weakcredentials",
			},
			Type:           detector.TypeVulnerability,
			Title:          title,
			Description:    description,
			Recommendation: recommendation,
			Sev:            &detector.Severity{Severity: detector.SeverityCritical},
		},
		Target: &detector.TargetDetails{Location: []string{"/etc/shadow"}},
		Extra:  problemDescription,
	}}, nil
}

func parseShadowFile(f fs.File) (map[string]string, error) {
	users := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) >= 2 {
			users[fields[0]] = fields[1]
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return users, nil
}
