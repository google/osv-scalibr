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

//go:build windows

// Package winlocal implements a weak passwords detector for local accounts on Windows.
package winlocal

import (
	"bufio"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/detector/weakcredentials/winlocal/samreg"
	"github.com/google/osv-scalibr/detector/weakcredentials/winlocal/systemreg"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
	"golang.org/x/sys/windows/registry"
)

var (
	//go:embed data/top100_nt_hashes.csv
	knownNTHashesFile string
	//go:embed data/top100_lm_hashes.csv
	knownLMHashesFile string
)

const (
	// Name of the detector.
	Name = "weakcredentials/winlocal"

	samDumpFile       = `C:\ProgramData\Scalibr\private\SAM`
	systemDumpFile    = `C:\ProgramData\Scalibr\private\SYSTEM`
	vulnRefLMPassword = "PASSWORD_HASH_LM_FORMAT"
	vulnRefWeakPass   = "WINDOWS_WEAK_PASSWORD"
)

// Detector is a SCALIBR Detector for weak passwords detector for local accounts on Windows.
type Detector struct {
	knownNTHashes map[string]string
	knownLMHashes map[string]string
}

// New returns a detector.
func New() detector.Detector {
	return &Detector{}
}

// userHashInfo contains the hashes of a user. Note that both hashes represents the same password.
type userHashInfo struct {
	username string
	lmHash   string
	ntHash   string
}

// Name of the detector.
func (Detector) Name() string { return Name }

// Version of the detector.
func (Detector) Version() int { return 0 }

// Requirements of the detector.
func (Detector) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{OS: plugin.OSWindows}
}

// RequiredExtractors returns an empty list as there are no dependencies.
func (Detector) RequiredExtractors() []string { return nil }

// DetectedFinding returns generic vulnerability information about what is detected.
func (d Detector) DetectedFinding() inventory.Finding {
	return inventory.Finding{
		GenericFindings: []*inventory.GenericFinding{
			d.findingForFormatLM(nil),
			d.findingForWeakPasswords(nil),
		},
	}
}

// Scan starts the scan.
func (d Detector) Scan(ctx context.Context, _ *scalibrfs.ScanRoot, _ *packageindex.PackageIndex) (inventory.Finding, error) {
	hashes, err := d.hashes(ctx)
	if err != nil || len(hashes) == 0 {
		return inventory.Finding{}, err
	}

	return d.internalScan(ctx, hashes)
}

// internalScan is the internal portion of the Scan function. The function was split in two to
// dissociate registry operation from finding the vulnerabilities to allow unit testing.
func (d Detector) internalScan(ctx context.Context, hashes []*userHashInfo) (inventory.Finding, error) {
	// first part of the detection: if any user's password is stored using the LM format, this is a
	// vulnerability given the weakness of the algorithm.
	var usersWithLM []string
	for _, user := range hashes {
		if user.lmHash != "" {
			usersWithLM = append(usersWithLM, user.username)
		}
	}

	var findings []*inventory.GenericFinding
	if len(usersWithLM) > 0 {
		target := &inventory.GenericFindingTargetDetails{Extra: fmt.Sprintf("%v", usersWithLM)}
		findings = append(findings, d.findingForFormatLM(target))
	}

	// then, we can actually try to find weak passwords.
	weakUsers, err := d.bruteforce(ctx, hashes)
	if err != nil {
		return inventory.Finding{}, err
	}

	if len(weakUsers) > 0 {
		target := &inventory.GenericFindingTargetDetails{Extra: fmt.Sprintf("%v", weakUsers)}
		findings = append(findings, d.findingForWeakPasswords(target))
	}

	return inventory.Finding{GenericFindings: findings}, nil
}

// findingForFormatLM creates a Scalibr finding when passwords are stored using the LM format.
func (d Detector) findingForFormatLM(target *inventory.GenericFindingTargetDetails) *inventory.GenericFinding {
	return &inventory.GenericFinding{
		Adv: &inventory.GenericFindingAdvisory{
			ID: &inventory.AdvisoryID{
				Publisher: "GOOGLE",
				Reference: vulnRefLMPassword,
			},
			Title:          "Password hashes are stored in the LM format",
			Sev:            inventory.SeverityHigh,
			Description:    "Password hashes are stored in the LM format. Please switch local storage to use NT format and regenerate the hashes.",
			Recommendation: "Change the password of the user after changing the storage format.",
		},
		Target: target,
	}
}

// findingForWeakPasswords creates a Scalibr finding when passwords were found from the
// dictionaries.
func (d Detector) findingForWeakPasswords(target *inventory.GenericFindingTargetDetails) *inventory.GenericFinding {
	return &inventory.GenericFinding{
		Adv: &inventory.GenericFindingAdvisory{
			ID: &inventory.AdvisoryID{
				Publisher: "GOOGLE",
				Reference: vulnRefWeakPass,
			},
			Title:          "Weak passwords on Windows",
			Sev:            inventory.SeverityCritical,
			Description:    "Some passwords were identified as being weak.",
			Recommendation: "Change the password of the user affected users.",
		},
		Target: target,
	}
}

// saveSensitiveReg saves a registry key to a file. It handles registries that are considered
// sensitive and thus will try to take measures to limit access to the file.
// Note that it is still the responsibility of the caller to delete the file once it is no longer
// needed.
func (d Detector) saveSensitiveReg(hive registry.Key, regPath string, file string) error {
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return err
	}

	if _, err := os.Stat(file); err == nil || !os.IsNotExist(err) {
		if err := os.Remove(file); err != nil {
			return err
		}
	}

	key, err := registry.OpenKey(hive, regPath, registry.ALL_ACCESS)
	if err != nil {
		return err
	}

	defer key.Close()

	// Only give full access to SYSTEM but allow admins to delete the file.
	//
	// O:SY; Owner: SYSTEM
	// G:SY; Group: SYSTEM
	// D:PAI; DACL - SDDL_AUTO_INHERITED, SDDL_PROTECTED
	//
	// (A;;FA;;;SY); SDDL_ACCESS_ALLOWED - FULL_ACCESS - SYSTEM
	// (A;;SD;;;BA); SDDL_ACCESS_ALLOWED - SDDL_STANDARD_DELETE - Builtin admins
	sddl := "O:SYG:SYD:PAI(A;;FA;;;SY)(A;;SD;;;BA)"
	return RegSaveKey(syscall.Handle(key), file, sddl)
}

func (d Detector) dumpSAM(samFile string) (*samreg.SAMRegistry, error) {
	if err := d.saveSensitiveReg(registry.LOCAL_MACHINE, `SAM`, samFile); err != nil {
		return nil, err
	}

	reg, err := samreg.NewFromFile(samFile)
	if err != nil {
		os.Remove(samFile)
		return nil, err
	}

	return reg, nil
}

func (d Detector) dumpSYSTEM(systemFile string) (*systemreg.SystemRegistry, error) {
	if err := d.saveSensitiveReg(registry.LOCAL_MACHINE, `SYSTEM`, systemFile); err != nil {
		return nil, err
	}

	reg, err := systemreg.NewFromFile(systemFile)
	if err != nil {
		os.Remove(systemFile)
		return nil, err
	}

	return reg, nil
}

// loadDictionary loads a dictionary (*in place*) of known passwords from a file.
// Each line is expected to be in the format:
//
//	hash;clearPass
func (d Detector) loadDictionary(file string, dict map[string]string) error {
	if dict == nil {
		return errors.New("dictionary is nil")
	}

	scanner := bufio.NewScanner(strings.NewReader(file))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ";")
		if len(parts) != 2 {
			continue
		}

		hash := parts[0]
		clearPass := parts[1]
		dict[hash] = clearPass
	}

	return nil
}

func (d Detector) knownHashes() (map[string]string, map[string]string, error) {
	if d.knownNTHashes == nil {
		d.knownNTHashes = make(map[string]string)
		if err := d.loadDictionary(knownNTHashesFile, d.knownNTHashes); err != nil {
			return nil, nil, err
		}
	}

	if d.knownLMHashes == nil {
		d.knownLMHashes = make(map[string]string)
		if err := d.loadDictionary(knownLMHashesFile, d.knownLMHashes); err != nil {
			return nil, nil, err
		}
	}

	return d.knownNTHashes, d.knownLMHashes, nil
}

func (d Detector) hashesForUser(sam *samreg.SAMRegistry, rid string, derivedKey []byte) (*userHashInfo, error) {
	info, err := sam.UserInfo(rid)
	if err != nil {
		return nil, err
	}

	enabled, err := info.Enabled()
	if err != nil {
		return nil, err
	}

	// if the user is disabled, we do not waste cycle cracking their password.
	if !enabled {
		return nil, nil
	}

	username, err := info.Username()
	if err != nil {
		return nil, err
	}

	lmHash, ntHash, err := info.Hashes(derivedKey)
	if err != nil {
		return nil, err
	}

	return &userHashInfo{
		username: username,
		lmHash:   fmt.Sprintf("%X", string(lmHash)),
		ntHash:   fmt.Sprintf("%X", string(ntHash)),
	}, nil
}

// hashes returns the hashes of all (enabled) users on the system.
func (d Detector) hashes(ctx context.Context) ([]*userHashInfo, error) {
	system, err := d.dumpSYSTEM(systemDumpFile)
	if err != nil {
		return nil, err
	}

	defer os.Remove(systemDumpFile)
	defer system.Close()

	syskey, err := system.Syskey()
	if err != nil {
		return nil, err
	}

	sam, err := d.dumpSAM(samDumpFile)
	if err != nil {
		return nil, err
	}

	defer os.Remove(samDumpFile)
	defer sam.Close()

	derivedKey, err := sam.DeriveSyskey(syskey)
	if err != nil {
		return nil, err
	}

	rids, err := sam.UsersRIDs()
	if err != nil {
		return nil, err
	}

	var users []*userHashInfo
	for _, rid := range rids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		user, err := d.hashesForUser(sam, rid, derivedKey)
		if err != nil {
			return nil, err
		}

		// there was no error but no hashes were found. Most likely the user was disabled.
		if user == nil {
			continue
		}

		users = append(users, user)
	}

	return users, nil
}

func (d Detector) bruteforce(ctx context.Context, hashes []*userHashInfo) (map[string]string, error) {
	knownNTHashes, knownLMHashes, err := d.knownHashes()
	if err != nil {
		return nil, err
	}

	results := make(map[string]string)

	for _, user := range hashes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if len(user.lmHash) > 0 {
			if password, ok := knownLMHashes[user.lmHash]; ok {
				results[user.username] = password
				continue
			}
		}

		if len(user.ntHash) > 0 {
			if password, ok := knownNTHashes[user.ntHash]; ok {
				results[user.username] = password
				continue
			}
		}
	}

	return results, nil
}
