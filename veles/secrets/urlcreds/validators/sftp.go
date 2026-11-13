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

package validators

import (
	"context"
	"net"
	"net/url"

	"github.com/google/osv-scalibr/veles"
	"golang.org/x/crypto/ssh"
)

// SFTPValidator validates sftp URL credentials.
type SFTPValidator struct {
	// DialContext optionally overrides destination filtering for trusted callers.
	DialContext func(context.Context, string, string) (net.Conn, error)
}

// Validate validates sftp URL credentials.
//
// Note: ssh.NewClientConn is used instead of ssh.Dial because ssh.Dial does not accept a context.
func (s *SFTPValidator) Validate(ctx context.Context, u *url.URL) (veles.ValidationStatus, error) {
	dial := s.DialContext
	if dial == nil {
		dial = dialPublicContext
	}
	rawConn, err := dial(ctx, "tcp", u.Host)
	if err != nil {
		return veles.ValidationFailed, err
	}
	defer rawConn.Close()

	// Set a deadline otherwise the SSH handshake may stall indefinitely
	if err := setDeadline(ctx, rawConn); err != nil {
		return veles.ValidationFailed, err
	}

	pass, _ := u.User.Password()
	config := &ssh.ClientConfig{
		User:            u.User.Username(),
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		// Timeout:      Ignored when using NewClientConn
	}
	sshConn, _, _, err := ssh.NewClientConn(rawConn, u.Host, config)
	if err != nil {
		return veles.ValidationInvalid, nil
	}
	defer sshConn.Close()
	return veles.ValidationValid, nil
}
