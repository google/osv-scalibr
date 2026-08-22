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
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/google/osv-scalibr/veles"
)

const (
	// AMQP 0-9-1 frame constants.
	amqpFrameMethod = 1
	amqpFrameEnd    = 0xCE

	// Connection class and methods.
	amqpClassConnection = 10
	amqpMethodStart     = 10
	amqpMethodStartOK   = 11
	amqpMethodTune      = 30
	amqpMethodClose     = 50
	amqpMethodSecure    = 20

	// Default ports.
	defaultAMQPPort  = "5672"
	defaultAMQPSPort = "5671"
)

// amqpProtocolHeader is the AMQP 0-9-1 protocol header sent by the client to initiate the connection.
var amqpProtocolHeader = []byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}

// AMQPValidator validates AMQP URL credentials by performing the AMQP 0-9-1 handshake.
type AMQPValidator struct {
	UseTLS bool
}

// Validate connects to the AMQP server and attempts SASL PLAIN authentication.
func (a *AMQPValidator) Validate(ctx context.Context, u *url.URL) (veles.ValidationStatus, error) {
	timeout := 10 * time.Second
	addr := amqpHostWithDefaultPort(u.Host, a.defaultPort())

	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return veles.ValidationFailed, err
	}
	defer rawConn.Close()

	if err := rawConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return veles.ValidationFailed, errors.New("error setting connection deadline")
	}

	var conn io.ReadWriter = rawConn
	if a.UseTLS {
		tlsConn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return veles.ValidationFailed, fmt.Errorf("TLS handshake failed: %w", err)
		}
		conn = tlsConn
	}

	// Send AMQP 0-9-1 protocol header.
	if _, err := conn.Write(amqpProtocolHeader); err != nil {
		return veles.ValidationFailed, fmt.Errorf("error sending protocol header: %w", err)
	}

	// Read Connection.Start from the server.
	classID, methodID, err := amqpReadMethodFrame(conn)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("error reading Connection.Start: %w", err)
	}
	if classID != amqpClassConnection || methodID != amqpMethodStart {
		return veles.ValidationFailed, fmt.Errorf("expected Connection.Start, got class=%d method=%d", classID, methodID)
	}

	// Send Connection.Start-Ok with SASL PLAIN credentials.
	pass, _ := u.User.Password()
	if err := amqpWriteStartOK(conn, u.User.Username(), pass); err != nil {
		return veles.ValidationFailed, fmt.Errorf("error sending Connection.Start-Ok: %w", err)
	}

	// Read the server response.
	// Connection.Tune means authentication succeeded.
	// Connection.Close means authentication failed (ACCESS_REFUSED).
	// Connection.Secure means the server wants additional SASL steps (treat as failed).
	classID, methodID, err = amqpReadMethodFrame(conn)
	if err != nil {
		// If the server closes the connection, authentication failed.
		return veles.ValidationInvalid, nil
	}
	if classID == amqpClassConnection && methodID == amqpMethodTune {
		return veles.ValidationValid, nil
	}
	if classID == amqpClassConnection && (methodID == amqpMethodClose || methodID == amqpMethodSecure) {
		return veles.ValidationInvalid, nil
	}
	return veles.ValidationFailed, fmt.Errorf("unexpected response: class=%d method=%d", classID, methodID)
}

func (a *AMQPValidator) defaultPort() string {
	if a.UseTLS {
		return defaultAMQPSPort
	}
	return defaultAMQPPort
}

// amqpHostWithDefaultPort adds a default port to the host if none is specified.
func amqpHostWithDefaultPort(host, defaultPort string) string {
	if _, _, err := net.SplitHostPort(host); err != nil {
		return net.JoinHostPort(host, defaultPort)
	}
	return host
}

// amqpReadMethodFrame reads a single AMQP 0-9-1 method frame and returns the class and method IDs.
func amqpReadMethodFrame(r io.Reader) (classID, methodID uint16, err error) {
	// Frame header: type(1) + channel(2) + size(4) = 7 bytes.
	header := make([]byte, 7)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, 0, fmt.Errorf("error reading frame header: %w", err)
	}

	frameType := header[0]
	if frameType != amqpFrameMethod {
		return 0, 0, fmt.Errorf("expected method frame (type 1), got type %d", frameType)
	}

	size := binary.BigEndian.Uint32(header[3:7])

	// Read payload + frame end byte.
	buf := make([]byte, size+1)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, 0, fmt.Errorf("error reading frame payload: %w", err)
	}

	if buf[size] != amqpFrameEnd {
		return 0, 0, errors.New("invalid frame end marker")
	}

	if size < 4 {
		return 0, 0, errors.New("payload too short for method frame")
	}

	classID = binary.BigEndian.Uint16(buf[0:2])
	methodID = binary.BigEndian.Uint16(buf[2:4])
	return classID, methodID, nil
}

// amqpWriteStartOK writes a Connection.Start-Ok method frame with SASL PLAIN authentication.
func amqpWriteStartOK(w io.Writer, username, password string) error {
	// SASL PLAIN response: \x00username\x00password
	saslResponse := "\x00" + username + "\x00" + password
	mechanism := "PLAIN"
	locale := "en_US"

	// Method payload:
	//   class_id(2) + method_id(2)
	//   + client_properties: empty table = uint32(0)
	//   + mechanism: short-string
	//   + response: long-string
	//   + locale: short-string
	payloadSize := 4 + // class_id + method_id
		4 + // empty client_properties table
		1 + len(mechanism) + // short-string: mechanism
		4 + len(saslResponse) + // long-string: SASL response
		1 + len(locale) // short-string: locale

	frame := make([]byte, 7+payloadSize+1)
	frame[0] = amqpFrameMethod
	binary.BigEndian.PutUint16(frame[1:3], 0)                   // channel 0
	binary.BigEndian.PutUint32(frame[3:7], uint32(payloadSize)) // payload size
	offset := 7

	binary.BigEndian.PutUint16(frame[offset:], amqpClassConnection)
	offset += 2
	binary.BigEndian.PutUint16(frame[offset:], amqpMethodStartOK)
	offset += 2

	// Empty client_properties table.
	binary.BigEndian.PutUint32(frame[offset:], 0)
	offset += 4

	// Mechanism: short-string "PLAIN".
	frame[offset] = byte(len(mechanism))
	offset++
	copy(frame[offset:], mechanism)
	offset += len(mechanism)

	// SASL response: long-string.
	binary.BigEndian.PutUint32(frame[offset:], uint32(len(saslResponse)))
	offset += 4
	copy(frame[offset:], saslResponse)
	offset += len(saslResponse)

	// Locale: short-string "en_US".
	frame[offset] = byte(len(locale))
	offset++
	copy(frame[offset:], locale)
	offset += len(locale)

	frame[offset] = amqpFrameEnd

	_, err := w.Write(frame)
	return err
}
