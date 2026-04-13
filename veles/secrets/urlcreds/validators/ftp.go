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
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"net/url"

	"github.com/google/osv-scalibr/veles"
)

// FTPValidator validates an URL credential with an ftp schema.
type FTPValidator struct{}

// Validate attempts to connect and authenticate to the FTP server.
func (f *FTPValidator) Validate(ctx context.Context, u *url.URL) (veles.ValidationStatus, error) {
	// Establish the connection.
	conn, err := ftpDial(ctx, u.Host)
	if err != nil {
		return veles.ValidationFailed, err
	}
	defer conn.Close()

	// Attempt authentication.
	pass, _ := u.User.Password()
	if err := ftpLogin(conn, u.User.Username(), pass); err != nil {
		// If login fails (but connection worked), it's Invalid credentials, not a Failed connection.
		return veles.ValidationInvalid, nil
	}

	return veles.ValidationValid, nil
}

// ftpDial connects to the address using the provided context and establishes a textproto connection.
// It reads the initial 220 greeting from the server.
func ftpDial(ctx context.Context, addr string) (*textproto.Conn, error) {
	rawConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	tp := textproto.NewConn(rawConn)
	// FTP servers send a 220 greeting immediately upon connection.
	if _, _, err := tp.ReadResponse(220); err != nil {
		tp.Close()
		return nil, fmt.Errorf("failed to read greeting: %w", err)
	}

	return tp, nil
}

func ftpLogin(tp *textproto.Conn, user, pass string) error {
	id, err := tp.Cmd("USER %s", user)
	if err != nil {
		return err
	}

	tp.StartResponse(id)
	// Pass 0 to disable automatic status code checking,
	// both 230 and 331 are ok here.
	code, _, err := tp.ReadResponse(0)
	tp.EndResponse(id)
	if err != nil {
		return err
	}

	switch code {
	case 230:
		// User logged in directly (no password needed).
		return nil
	case 331:
		// Password required.
		id, err = tp.Cmd("PASS %s", pass)
		if err != nil {
			return err
		}
		tp.StartResponse(id)
		_, _, err = tp.ReadResponse(230)
		tp.EndResponse(id)
		if err != nil {
			return fmt.Errorf("password rejected: %w", err)
		}
	case 530:
		return errors.New("login incorrect")
	default:
		return fmt.Errorf("unexpected code after USER: %d", code)
	}

	_, _ = tp.Cmd("QUIT")
	return nil
}
