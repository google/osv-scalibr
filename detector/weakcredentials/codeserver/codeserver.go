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

// Package codeserver contains a detector for weak credentials in Code-Server https://github.com/coder/code-server/.
package codeserver

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/cookiejar"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/osv-scalibr/detector"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
)

/*
** To test this detector, you can use the following docker image:
**
** docker run -it --name code-server-noauth -p 127.0.0.1:8080:8080  \
**   -v "/root/code-server-configs/config-without-auth.yaml:/root/.config/code-server/config.yaml" \
**   -v "$PWD:/home/coder/project" \
**   -u "$(id -u):$(id -g)" \
**   -e "DOCKER_USER=$USER" \
**   codercom/code-server:latest
**
** with config-without-auth.yaml being:
**  bind-addr: 127.0.0.1:8080
**  auth: none
**  password: doesntmatter
**  cert: false
 */

const (
	// Name of the detector.
	Name = "weakcredentials/codeserver"

	// The number of requests that this detector sends. Used to compute an upper-bound for certain
	// timeouts.
	numRequests = 1

	// defaultClientTimeout is the default timeout for the HTTP client. This means that this timeout
	// get applied to *every request*. So, to get the timeout of the detector it has to be multiplied
	// by the number of HTTP requests.
	defaultClientTimeout = 1 * time.Second

	// This target will specifically target a local instance of Code-Server. Note that we use
	// 127.0.0.2 to exclude instances only listening on localhost.
	defaultAddress = "127.0.0.2"
	// The default address for MacOS, as only 127.0.0.1 is enabled by default.
	defaultMacOSAddress = "localhost"
	defaultPort         = 49363
)

// Patterns to differentiate enabled authentication from disabled.
// Tested on Code-Server v4.99.0.
var (
	authDisabledPattern1 = `<meta id="vscode-workbench-auth-session" data-settings="">`
	authDisabledPattern2 = `globalThis._VSCODE_FILE_ROOT`
)

// Config for this detector.
type Config struct {
	Remote        string
	ClientTimeout time.Duration
}

// Detector is a SCALIBR Detector for weak/guessable passwords for the Code-Server service.
type Detector struct {
	config Config
}

// DefaultConfig returns the default config for this detector.
func DefaultConfig() Config {
	return defaultConfigWithOS(runtime.GOOS)
}

func defaultConfigWithOS(os string) Config {
	address := defaultAddress
	if os == "darwin" {
		address = defaultMacOSAddress
	}
	return Config{
		Remote:        "http://" + net.JoinHostPort(address, strconv.Itoa(defaultPort)),
		ClientTimeout: defaultClientTimeout,
	}
}

// New returns a detector.
func New(cfg Config) detector.Detector {
	return &Detector{
		config: cfg,
	}
}

// NewDefault returns a detector with the default config settings.
func NewDefault() detector.Detector {
	return New(DefaultConfig())
}

// Name of the detector.
func (Detector) Name() string { return Name }

// Version of the detector.
func (Detector) Version() int { return 0 }

// Requirements of the detector.
func (Detector) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		RunningSystem: true,
	}
}

// RequiredExtractors returns an empty list as there are no dependencies.
func (Detector) RequiredExtractors() []string {
	return []string{}
}

// DetectedFinding returns generic vulnerability information about what is detected.
func (d Detector) DetectedFinding() inventory.Finding {
	return d.finding()
}

func (Detector) finding() inventory.Finding {
	return inventory.Finding{GenericFindings: []*inventory.GenericFinding{
		&inventory.GenericFinding{
			Adv: &inventory.GenericFindingAdvisory{
				ID: &inventory.AdvisoryID{
					Publisher: "SCALIBR",
					Reference: "CODESERVER_WEAK_CREDENTIALS",
				},
				Title:          "Code-Server instance without authentication",
				Description:    "Your Code-Server instance has no authentication enabled. This means that the instance is vulnerable to remote code execution.",
				Recommendation: "Enforce an authentication in the config.yaml file. See https://github.com/coder/code-server/blob/main/docs/FAQ.md#how-does-the-config-file-work for more details.",
				Sev:            inventory.SeverityCritical,
			},
		},
	}}
}

// Scan starts the scan.
func (d Detector) Scan(ctx context.Context, _ *scalibrfs.ScanRoot, _ *packageindex.PackageIndex) (inventory.Finding, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return inventory.Finding{}, err
	}

	client := &http.Client{
		Timeout: d.config.ClientTimeout,
		Jar:     jar,
	}
	timeout := d.config.ClientTimeout*numRequests + 100*time.Millisecond
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	vuln, err := checkAuth(ctx, client, d.config.Remote)
	if err != nil {
		return inventory.Finding{}, err
	}

	if !vuln {
		return inventory.Finding{}, nil
	}

	return d.finding(), nil
}

func checkAuth(ctx context.Context, client *http.Client, target string) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false, nil
	}
	resp, err := client.Do(req)
	if err != nil {
		// Up to and including this point, we swallow errors as we consider a failure to connect to be a
		// non-vulnerable instance.
		return false, nil
	}

	scanner := bufio.NewScanner(resp.Body)
	defer resp.Body.Close()

	matched1 := false
	for scanner.Scan() {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}

		line := scanner.Text()

		if !matched1 {
			if strings.Contains(line, authDisabledPattern1) {
				matched1 = true
			}
		} else {
			if strings.Contains(line, authDisabledPattern2) {
				return true, nil
			}
		}
	}

	return false, nil
}
