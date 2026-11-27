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

// Package sshhole implements a SCALIBR detector for the CVE-2026-123158 (OpenSSH + musl)
// pre-authentication password bypass vulnerability across both container images
// (static filesystem / layer scanning) and live systems.
package sshhole

import (
	"bufio"
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/semantic"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name of the detector.
	Name = "misc/sshhole"
)

var (
	// Matches portable OpenSSH release banners such as "OpenSSH_10.6p1" or
	// "OpenSSH_10.3p1". The "p<N>" suffix is required so that the client
	// compatibility patterns compiled into sshd (e.g. "OpenSSH_3.0*",
	// "OpenSSH_6.6.1*" in compat.c) are not mistaken for the sshd version.
	openSSHVersionRegex = regexp.MustCompile(`OpenSSH_(\d+\.\d+p\d+)`)

	// Matches generic OpenSSH versions across distributions (e.g. "OpenSSH_8.8p1",
	// "8.8p1", "8.8_p1-r1", "1:9.2p1-2+deb12u3", "9.9p1_1").
	openSSHGenericVerRegex = regexp.MustCompile(`^(?:OpenSSH_)?(?:\d+:)?(\d+)\.(\d+)(?:_?p(\d+))?(?:-r(\d+))?`)

	// Candidate paths for the sshd binary inside the scanned root.
	sshdBinaryPaths = []string{
		"usr/sbin/sshd",
		"sbin/sshd",
		"usr/local/sbin/sshd",
		"usr/bin/sshd",
		"bin/sshd",
		"usr/local/bin/sshd",
	}
)

// CommandRunner executes a command on a live system and returns its output.
type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

func defaultCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Detector is a SCALIBR Detector for the CVE-2026-123158 (OpenSSH + musl) authentication bypass.
type Detector struct {
	cmdRunner CommandRunner
}

// New returns a new CVE-2026-123158 detector.
func New(_ *cpb.PluginConfig) (detector.Detector, error) {
	return &Detector{cmdRunner: defaultCommandRunner}, nil
}

// Name of the detector.
func (Detector) Name() string { return Name }

// Version of the detector.
func (Detector) Version() int { return 0 }

// Requirements leaves DirectFS and RunningSystem false so the detector can run
// in both Container Scanning (virtual FS) and live-system scanning (Linux host).
func (Detector) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// RequiredExtractors returns the Alpine APK extractor so PackageIndex contains
// installed OpenSSH and musl packages when scanning Alpine hosts or containers.
func (Detector) RequiredExtractors() []string {
	return []string{apk.Name}
}

// DetectedFinding returns generic vulnerability information about what is detected.
func (Detector) DetectedFinding() inventory.Finding {
	return findingForTarget(nil)
}

func findingForTarget(target *inventory.GenericFindingTargetDetails) inventory.Finding {
	return inventory.Finding{GenericFindings: []*inventory.GenericFinding{{
		Adv: &inventory.GenericFindingAdvisory{
			ID: &inventory.AdvisoryID{
				Publisher: "SCALIBR",
				Reference: "openssh-musl-authentication-bypass",
			},
			Title: "CVE-2026-123158 - OpenSSH + musl Pre-Authentication Password Bypass",
			Description: "CVE-2026-123158: OpenSSH (< 10.6p2) linked against musl libc and running without PAM " +
				"permits remote password authentication bypass for any account whose password " +
				"field is '*' in /etc/shadow (or in /etc/passwd when no shadow entry exists). " +
				"When PasswordAuthentication is enabled and pick_salt() borrows a $6$ (SHA-512), " +
				"$5$ (SHA-256), or $2a$/$2b$/$2y$ (bcrypt) salt from another account, sending a " +
				"257-1024 byte password causes musl's crypt() to return '*', matching '*'.",
			Recommendation: "1) Upgrade OpenSSH to 10.6p2 or a patched distribution package " +
				"(e.g., Alpine openssh >= 10.3_p1-r2), 2) Set 'PasswordAuthentication no' in " +
				"/etc/ssh/sshd_config, or 3) Replace '*' with '!' in /etc/shadow and /etc/passwd " +
				"for passwordless or key-only accounts.",
			Sev: inventory.SeverityCritical,
		},
		Target: target,
	}}}
}

// Scan checks for CVE-2026-123158 in both container filesystems and live hosts.
func (d Detector) Scan(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex) (inventory.Finding, error) {
	if ctx.Err() != nil {
		return inventory.Finding{}, ctx.Err()
	}
	if scanRoot == nil || scanRoot.FS == nil {
		return inventory.Finding{}, nil
	}

	// 1. Inspect sshd binary / environment for musl libc and PAM linkage.
	binInfo := inspectSSHDBinary(scanRoot.FS)
	if !binInfo.sshdPresent || !binInfo.isMusl {
		return inventory.Finding{}, nil
	}

	// 2. Check if OpenSSH is in the vulnerable version range (< 10.6p2 and unpatched).
	isVulnVer, verStr := d.checkVulnerableVersion(ctx, scanRoot, px, binInfo)
	if !isVulnVer {
		return inventory.Finding{}, nil
	}

	// 3. Determine effective sshd configuration (live `sshd -T` on live hosts,
	//    or static parsing of /etc/ssh/sshd_config + Include files for containers).
	sshCfg := d.resolveSSHDConfig(ctx, scanRoot, binInfo)
	if sshCfg.usePAM || !sshCfg.passwordAuthentication {
		return inventory.Finding{}, nil
	}

	// 4 & 5. Check /etc/passwd and /etc/shadow (including the "no shadow" fallback)
	//        for target '*' accounts and a borrowable $6$/$5$/$2a$/$2b$/$2y$ salt.
	vulnUsers, saltSource, borrowedAlg, err := checkAccountsAndSalt(scanRoot.FS, sshCfg)
	if err != nil || len(vulnUsers) == 0 || borrowedAlg == "" {
		return inventory.Finding{}, err
	}

	extra := fmt.Sprintf(
		"openssh_version=%s; config_source=%s; borrowed_salt=%s (%s); vulnerable_accounts=%s",
		verStr,
		sshCfg.source,
		borrowedAlg,
		saltSource,
		strings.Join(vulnUsers, ","),
	)
	return findingForTarget(&inventory.GenericFindingTargetDetails{Extra: extra}), nil
}

type sshdBinaryInfo struct {
	sshdPresent      bool
	sshdPath         string
	isMusl           bool
	hasNonMuslInterp bool
	hasLibPAM        bool
	rodataVersion    string
}

// inspectSSHDBinary inspects the sshd ELF binary and filesystem
// without executing any commands, making it safe for container image scanning.
func inspectSSHDBinary(fsys scalibrfs.FS) sshdBinaryInfo {
	var info sshdBinaryInfo

	for _, candidate := range sshdBinaryPaths {
		f, err := fsys.Open(candidate)
		if err != nil {
			continue
		}
		info.sshdPresent = true
		info.sshdPath = candidate
		parseELFAndBanner(f, &info)
		f.Close()
		break
	}

	if !info.isMusl && !info.hasNonMuslInterp && hasMuslLoader(fsys) {
		info.isMusl = true
	}

	return info
}

func parseELFAndBanner(f fs.File, info *sshdBinaryInfo) {
	data, err := io.ReadAll(f)
	if err != nil {
		return
	}
	if m := openSSHVersionRegex.FindSubmatch(data); len(m) >= 2 {
		info.rodataVersion = string(m[1])
	}
	if bytes.Contains(data, []byte("ld-musl")) || bytes.Contains(data, []byte("libc.musl")) {
		info.isMusl = true
	}
	if bytes.Contains(data, []byte("libpam.so")) || bytes.Contains(data, []byte("pam_start")) {
		info.hasLibPAM = true
	}

	ef, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return
	}
	defer ef.Close()

	elfHasMusl := false
	if libs, err := ef.ImportedLibraries(); err == nil {
		for _, lib := range libs {
			if strings.Contains(lib, "musl") {
				elfHasMusl = true
			}
			if strings.HasPrefix(lib, "libpam.so") {
				info.hasLibPAM = true
			}
		}
	}
	if interp := ef.Section(".interp"); interp != nil {
		if b, err := interp.Data(); err == nil && len(bytes.TrimRight(b, "\x00")) > 0 {
			if strings.Contains(string(b), "musl") {
				elfHasMusl = true
			} else if !elfHasMusl {
				info.hasNonMuslInterp = true
			}
		}
	}
	if elfHasMusl {
		info.isMusl = true
		info.hasNonMuslInterp = false
	} else if info.hasNonMuslInterp {
		info.isMusl = false
	}
}

func hasMuslLoader(fsys scalibrfs.FS) bool {
	for _, dir := range []string{"lib", "usr/lib", "lib64", "usr/lib64", "etc"} {
		entries, err := fs.ReadDir(fsys, dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			// Matches loaders (ld-musl-<arch>.so.1), loader path files
			// (ld-musl-<arch>.path), and Alpine's libc.musl-<arch>.so.1.
			if strings.HasPrefix(name, "ld-musl-") || strings.HasPrefix(name, "libc.musl-") {
				return true
			}
		}
	}
	return false
}

// checkVulnerableVersion determines whether the installed OpenSSH version is < 10.6p2
// and not a patched package revision.
func (d Detector) checkVulnerableVersion(ctx context.Context, scanRoot *scalibrfs.ScanRoot, px *packageindex.PackageIndex, binInfo sshdBinaryInfo) (bool, string) {
	// 1. Check PackageIndex to inspect openssh* package version strings for
	// distro-backported revision suffixes (e.g. Alpine apk -r2 / -r6) that
	// are not present in the binary's .rodata OpenSSH_X.YpZ banner.
	if px != nil {
		allPkgs := px.GetAll()
		for _, pkgName := range []string{"openssh-server", "openssh-server-pam", "openssh", "net-misc/openssh"} {
			for _, pkg := range allPkgs {
				if pkg.Name != pkgName || pkg.Version == "" {
					continue
				}
				alpineBackports := pkg.PURLType == purl.TypeApk
				return isVulnerableOpenSSHVersion(pkg.Version, alpineBackports), fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)
			}
		}
	}

	// 2. Check embedded OpenSSH version string extracted from the sshd binary.
	if binInfo.rodataVersion != "" {
		return isVulnerableOpenSSHVersion(binInfo.rodataVersion, false), binInfo.rodataVersion
	}

	// 3. Live-system fallback: run `sshd -V` or `ssh -V` when scanning the live host root.
	if isLiveHostRoot(scanRoot) && d.cmdRunner != nil {
		sshdCmd := "sshd"
		if binInfo.sshdPath != "" && scanRoot.Path != "" {
			sshdCmd = filepath.Join(scanRoot.Path, filepath.FromSlash(binInfo.sshdPath))
		}
		for _, bin := range []string{sshdCmd, "ssh"} {
			out, _ := d.cmdRunner(ctx, bin, "-V")
			if m := openSSHVersionRegex.FindSubmatch(out); len(m) >= 2 {
				ver := string(m[1])
				return isVulnerableOpenSSHVersion(ver, false), ver
			}
		}
	}

	return false, ""
}

func isLiveHostRoot(scanRoot *scalibrfs.ScanRoot) bool {
	return scanRoot != nil && !scanRoot.IsVirtual() && path.Clean(filepath.ToSlash(scanRoot.Path)) == "/"
}

// isVulnerableOpenSSHVersion extracts (major, minor, patch) from any distribution
// OpenSSH version format (e.g. "OpenSSH_8.8p1", "8.8p1", "8.8_p1-r1", "1:9.2p1-2+deb12u3",
// "9.9p1_1") and checks whether it is < 10.6p2. When alpineBackports is true
// (the version came from an Alpine apk package), Alpine -r<N> revisions that
// carry the backported fix are treated as patched. Other distributions (e.g.
// Gentoo) also use -r<N> suffixes with unrelated numbering, so the table is not
// applied to them.
func isVulnerableOpenSSHVersion(verStr string, alpineBackports bool) bool {
	m := openSSHGenericVerRegex.FindStringSubmatch(strings.TrimSpace(verStr))
	if len(m) < 3 {
		return false
	}
	major, err := strconv.Atoi(m[1])
	if err != nil {
		return false
	}
	minor, err := strconv.Atoi(m[2])
	if err != nil {
		return false
	}
	patch := 0
	if m[3] != "" {
		patch, err = strconv.Atoi(m[3])
		if err != nil {
			return false
		}
	}

	// OpenSSH fixed CVE-2026-123158 upstream in 10.6p2.
	if major > 10 {
		return false
	}
	if major == 10 && (minor > 6 || (minor == 6 && patch >= 2)) {
		return false
	}

	// Respect Alpine backported fixes when a -r<N> revision suffix is present.
	revStr := ""
	if len(m) >= 5 {
		revStr = m[4]
	}
	if alpineBackports && revStr != "" {
		if v, err := semantic.ParseAlpineVersion(verStr); err == nil {
			if cmp106p2, err := v.CompareStr("10.6_p2"); err == nil && cmp106p2 >= 0 {
				return false
			}
		}
		if rev, err := strconv.Atoi(revStr); err == nil {
			switch {
			case major == 10 && minor == 3 && patch == 1 && rev >= 2:
				return false
			case major == 9 && minor == 9 && patch == 2 && rev >= 1:
				return false
			case major == 9 && minor == 9 && patch == 1 && rev >= 3:
				return false
			case major == 9 && minor == 7 && patch == 1 && rev >= 6:
				return false
			case major == 9 && minor == 6 && patch == 1 && rev >= 3:
				return false
			case major == 9 && minor == 3 && patch == 2 && rev >= 4:
				return false
			case major == 9 && minor == 1 && patch == 1 && rev >= 7:
				return false
			case major == 9 && minor == 0 && patch == 1 && rev >= 6:
				return false
			}
		}
	}

	return true
}

type sshdConfig struct {
	usePAM                 bool
	passwordAuthentication bool
	permitRootLogin        bool
	allowUsers             []string
	denyUsers              []string
	allowGroups            []string
	denyGroups             []string
	source                 string
}

func (d Detector) resolveSSHDConfig(ctx context.Context, scanRoot *scalibrfs.ScanRoot, binInfo sshdBinaryInfo) sshdConfig {
	// OpenSSH compiled-in defaults when directives are omitted from sshd_config:
	cfg := sshdConfig{
		usePAM:                 false,
		passwordAuthentication: true,
		permitRootLogin:        false, // defaults to prohibit-password
		source:                 "defaults",
	}

	// Use Case 1: Live-system mode. When scanning the live host root ("/"),
	// attempt `sshd -T` to evaluate the exact runtime configuration (including Includes).
	if isLiveHostRoot(scanRoot) && d.cmdRunner != nil {
		sshdCmd := "sshd"
		if binInfo.sshdPath != "" && scanRoot.Path != "" {
			sshdCmd = filepath.Join(scanRoot.Path, filepath.FromSlash(binInfo.sshdPath))
		}
		if out, err := d.cmdRunner(ctx, sshdCmd, "-T"); err == nil && len(out) > 0 {
			state := &sshdParseState{hasLibPAM: binInfo.hasLibPAM}
			parseSSHDReader(bytes.NewReader(out), scanRoot.FS, state, 0)
			applyParseState(&cfg, state)
			cfg.source = "sshd -T"
			return cfg
		}
	}

	// Use Case 2: Container scanning / static config file parsing via scanRoot.FS.
	state := &sshdParseState{hasLibPAM: binInfo.hasLibPAM}
	if parseSSHDFile(scanRoot.FS, "etc/ssh/sshd_config", state, 0) {
		applyParseState(&cfg, state)
		cfg.source = "/etc/ssh/sshd_config"
	}
	return cfg
}

type sshdParseState struct {
	hasLibPAM       bool
	seenUsePAM      bool
	usePAM          bool
	seenPasswdAuth  bool
	passwdAuth      bool
	seenPermitRoot  bool
	permitRootLogin bool
	allowUsers      []string
	denyUsers       []string
	allowGroups     []string
	denyGroups      []string
}

func applyParseState(cfg *sshdConfig, state *sshdParseState) {
	if state.seenUsePAM {
		cfg.usePAM = state.usePAM
	}
	if state.seenPasswdAuth {
		cfg.passwordAuthentication = state.passwdAuth
	}
	if state.seenPermitRoot {
		cfg.permitRootLogin = state.permitRootLogin
	}
	cfg.allowUsers = state.allowUsers
	cfg.denyUsers = state.denyUsers
	cfg.allowGroups = state.allowGroups
	cfg.denyGroups = state.denyGroups
}

const maxIncludeDepth = 5

func parseSSHDFile(fsys scalibrfs.FS, filePath string, state *sshdParseState, depth int) bool {
	if depth > maxIncludeDepth {
		return false
	}
	f, err := fsys.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()
	parseSSHDReader(f, fsys, state, depth)
	return true
}

func parseSSHDReader(r io.Reader, fsys scalibrfs.FS, state *sshdParseState, depth int) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip trailing comments (quoted values are not supported).
		if idx := strings.IndexByte(line, '#'); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		// Support both "Key Value" and "Key=Value" syntax.
		line = strings.Replace(line, "=", " ", 1)
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		val := strings.ToLower(fields[1])

		// Stop global directive parsing once a conditional Match block starts.
		if key == "match" {
			break
		}

		switch key {
		case "include":
			if fsys == nil || depth >= maxIncludeDepth {
				continue
			}
			for _, pattern := range fields[1:] {
				fsPattern := strings.TrimPrefix(filepath.ToSlash(pattern), "/")
				if !strings.HasPrefix(pattern, "/") {
					fsPattern = path.Join("etc/ssh", fsPattern)
				}
				matches, err := fs.Glob(fsys, fsPattern)
				if err != nil {
					continue
				}
				slices.Sort(matches)
				for _, m := range matches {
					parseSSHDFile(fsys, m, state, depth+1)
				}
			}
		case "usepam":
			if !state.seenUsePAM {
				state.seenUsePAM = true
				state.usePAM = state.hasLibPAM && (val == "yes")
			}
		case "passwordauthentication":
			if !state.seenPasswdAuth {
				state.seenPasswdAuth = true
				state.passwdAuth = (val == "yes")
			}
		case "permitrootlogin":
			if !state.seenPermitRoot {
				state.seenPermitRoot = true
				state.permitRootLogin = (val == "yes")
			}
		case "allowusers":
			state.allowUsers = append(state.allowUsers, fields[1:]...)
		case "denyusers":
			state.denyUsers = append(state.denyUsers, fields[1:]...)
		case "allowgroups":
			state.allowGroups = append(state.allowGroups, fields[1:]...)
		case "denygroups":
			state.denyGroups = append(state.denyGroups, fields[1:]...)
		}
	}
}

type passwdUser struct {
	name   string
	passwd string
	uid    string
	gid    string
	shell  string
}

// checkAccountsAndSalt emulates OpenSSH's shadow_pw(pw) and pick_salt() across
// /etc/passwd and /etc/shadow, including the "no shadow" fallback to /etc/passwd.
func checkAccountsAndSalt(fsys scalibrfs.FS, cfg sshdConfig) (vulnUsers []string, saltSource string, borrowedAlg string, err error) {
	passwdUsers, err := parsePasswd(fsys)
	if err != nil || len(passwdUsers) == 0 {
		return nil, "", "", err
	}
	shadowMap, err := parseShadow(fsys)
	if err != nil {
		// The "no shadow" fallback is only valid when /etc/shadow does not exist.
		// Any other error (e.g. EACCES on a non-root live scan) means the real
		// password state is unknown, so report the error instead of guessing.
		return nil, "", "", fmt.Errorf("reading /etc/shadow: %w", err)
	}
	var groups *groupDB
	if len(cfg.allowGroups) > 0 || len(cfg.denyGroups) > 0 {
		if groups, err = parseGroup(fsys); err != nil {
			return nil, "", "", fmt.Errorf("reading /etc/group: %w", err)
		}
	}

	var firstModularHash string
	var firstModularUser string
	var firstModularFromShadow bool

	for _, pw := range passwdUsers {
		// Emulate shadow_pw(pw) in openbsd-compat/xcrypt.c:
		// Default to pw->pw_passwd from /etc/passwd, and overwrite only if
		// getspnam(pw->pw_name) finds a record in /etc/shadow.
		effectiveHash := pw.passwd
		fromShadow := false
		if spw, ok := shadowMap[pw.name]; ok {
			effectiveHash = spw
			fromShadow = true
		}

		// Emulate pick_salt() in openbsd-compat/xcrypt.c:
		// Scan getpwent() in order and stop at the FIRST account whose
		// shadow_pw(pw) starts with '$' and has another '$'.
		if firstModularHash == "" && strings.HasPrefix(effectiveHash, "$") && strings.Contains(effectiveHash[1:], "$") {
			firstModularHash = effectiveHash
			firstModularUser = pw.name
			firstModularFromShadow = fromShadow
		}

		// Target account check: effectiveHash must be the literal 1-character "*".
		if effectiveHash != "*" {
			continue
		}
		if pw.uid == "0" && !cfg.permitRootLogin {
			continue
		}
		if isNonLoginShell(pw.shell) {
			continue
		}
		if !isUserAllowed(pw.name, groups.groupsFor(pw), cfg) {
			continue
		}
		sourceTag := "/etc/passwd(no-shadow)"
		if fromShadow {
			sourceTag = "/etc/shadow"
		}
		vulnUsers = append(vulnUsers, fmt.Sprintf("%s[%s]", pw.name, sourceTag))
	}

	if len(vulnUsers) == 0 || firstModularHash == "" {
		return nil, "", "", nil
	}

	// Only $6$ (SHA-512), $5$ (SHA-256), and $2a$/$2b$/$2y$ (bcrypt truncation in pick_salt)
	// cause musl's crypt() to return "*" on a 257-1024 byte password.
	// ($1$ MD5 has KEY_MAX=30000 > 1024, and no '$' hash falls back to "xx" DES.)
	for _, prefix := range []string{"$6$", "$5$", "$2a$", "$2b$", "$2y$"} {
		if strings.HasPrefix(firstModularHash, prefix) {
			loc := "/etc/passwd"
			if firstModularFromShadow {
				loc = "/etc/shadow"
			}
			return vulnUsers, fmt.Sprintf("%s in %s", firstModularUser, loc), prefix, nil
		}
	}

	return nil, "", "", nil
}

func isNonLoginShell(shell string) bool {
	if shell == "" {
		return false
	}
	if shell == "/dev/null" {
		return true
	}
	switch path.Base(shell) {
	case "nologin", "false", "sync", "halt", "shutdown":
		return true
	}
	return false
}

// isUserAllowed approximates the DenyUsers, AllowUsers, DenyGroups, and
// AllowGroups checks in sshd's allowed_user(). Patterns support the '*' and '?'
// wildcards. USER@HOST entries also depend on the client address, which the
// attacker chooses, so DenyUsers entries with a host part are ignored and
// AllowUsers entries with a host part are treated as matching on the user part.
func isUserAllowed(user string, groups []string, cfg sshdConfig) bool {
	for _, p := range cfg.denyUsers {
		if !strings.Contains(p, "@") && matchPattern(user, p) {
			return false
		}
	}
	if len(cfg.allowUsers) > 0 && !slices.ContainsFunc(cfg.allowUsers, func(p string) bool {
		if i := strings.LastIndexByte(p, '@'); i >= 0 {
			p = p[:i]
		}
		return matchPattern(user, p)
	}) {
		return false
	}
	if len(cfg.denyGroups) > 0 && slices.ContainsFunc(groups, func(g string) bool {
		return matchAnyPattern(g, cfg.denyGroups)
	}) {
		return false
	}
	if len(cfg.allowGroups) > 0 && !slices.ContainsFunc(groups, func(g string) bool {
		return matchAnyPattern(g, cfg.allowGroups)
	}) {
		return false
	}
	return true
}

func matchAnyPattern(s string, patterns []string) bool {
	return slices.ContainsFunc(patterns, func(p string) bool { return matchPattern(s, p) })
}

// matchPattern implements OpenSSH's match_pattern(): '*' matches any sequence
// and '?' matches exactly one character. Matching is case-sensitive.
func matchPattern(s, pattern string) bool {
	for pattern != "" {
		switch pattern[0] {
		case '*':
			pattern = pattern[1:]
			if pattern == "" {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if matchPattern(s[i:], pattern) {
					return true
				}
			}
			return false
		case '?':
			if s == "" {
				return false
			}
		default:
			if s == "" || s[0] != pattern[0] {
				return false
			}
		}
		s, pattern = s[1:], pattern[1:]
	}
	return s == ""
}

func parsePasswd(fsys scalibrfs.FS) ([]passwdUser, error) {
	f, err := fsys.Open("etc/passwd")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var users []passwdUser
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		u := passwdUser{
			name:   fields[0],
			passwd: fields[1],
			uid:    fields[2],
		}
		if len(fields) >= 4 {
			u.gid = fields[3]
		}
		if len(fields) >= 7 {
			u.shell = strings.TrimSpace(fields[6])
		}
		users = append(users, u)
	}
	return users, scanner.Err()
}

// parseShadow returns the password field of each /etc/shadow entry. It returns
// (nil, nil) only when /etc/shadow does not exist.
func parseShadow(fsys scalibrfs.FS) (map[string]string, error) {
	f, err := fsys.Open("etc/shadow")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	m := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 2 {
			m[fields[0]] = fields[1]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return m, nil
}

// groupDB holds the /etc/group data needed for AllowGroups / DenyGroups.
type groupDB struct {
	nameByGID map[string]string   // gid -> group name
	members   map[string][]string // user -> supplementary group names
}

// groupsFor returns the primary and supplementary group names of pw.
func (g *groupDB) groupsFor(pw passwdUser) []string {
	if g == nil {
		return nil
	}
	var out []string
	if name, ok := g.nameByGID[pw.gid]; ok {
		out = append(out, name)
	}
	return append(out, g.members[pw.name]...)
}

func parseGroup(fsys scalibrfs.FS) (*groupDB, error) {
	db := &groupDB{nameByGID: map[string]string{}, members: map[string][]string{}}
	f, err := fsys.Open("etc/group")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return db, nil
		}
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// name:password:gid:member1,member2
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		if _, ok := db.nameByGID[fields[2]]; !ok {
			db.nameByGID[fields[2]] = fields[0]
		}
		if len(fields) < 4 {
			continue
		}
		for _, m := range strings.Split(fields[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				db.members[m] = append(db.members[m], fields[0])
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return db, nil
}
