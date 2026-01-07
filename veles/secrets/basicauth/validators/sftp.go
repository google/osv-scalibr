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
	"errors"
	"net"
	"net/url"
	"time"

	"github.com/google/osv-scalibr/veles"
	"golang.org/x/crypto/ssh"
)

// SFTPValidator validates a Basic Auth URL with sftp schema.
type SFTPValidator struct{}

// Validate validates a Basic Auth URL with sftp schema.
func (s *SFTPValidator) Validate(ctx context.Context, u *url.URL) (veles.ValidationStatus, error) {
	pass, _ := u.User.Password()
	config := &ssh.ClientConfig{
		User:            u.User.Username(),
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	rawConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return veles.ValidationFailed, err
	}
	defer rawConn.Close()

	// set an hard timeout on the connection, using ssh.Dial results in long hangs
	if err := rawConn.SetDeadline(time.Now().Add(config.Timeout)); err != nil {
		return veles.ValidationFailed, errors.New("error setting connection deadline")
	}

	sshConn, _, _, err := ssh.NewClientConn(rawConn, u.Host, config)
	if err != nil {
		return veles.ValidationInvalid, nil
	}
	defer sshConn.Close()
	return veles.ValidationValid, nil
}
