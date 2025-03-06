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

package samreg

import (
	"bytes"
	"encoding/binary"
	"errors"

	"golang.org/x/text/encoding/unicode"
)

var (
	errReadOutOfBounds = errors.New("failed to read: out of bounds")
	errNoHashInfoFound = errors.New("no hash information found")
)

// userV is the V structure containing the user's information in the SAM hive.
// See https://web.archive.org/web/20190717124313/http://www.beginningtoseethelight.org/ntsecurity/index.htm#D3BC3F5643A17823
// for more information about the V structure.
type userV struct {
	rid    string
	header *userVHeader
	data   []byte
}

// newUserV parses the V structure from the provided buffer.
func newUserV(data []byte, rid string) (*userV, error) {
	entry := userVHeader{}
	if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &entry); err != nil {
		return nil, err
	}

	return &userV{
		rid:    rid,
		data:   data,
		header: &entry,
	}, nil
}

// read finds and reads data in the V structure from the provided offset and size.
func (s *userV) read(offset, size uint32) ([]byte, error) {
	offset += 0xCC
	limit := int(offset) + int(size)
	if len(s.data) < limit {
		return nil, errReadOutOfBounds
	}

	return s.data[offset:limit], nil
}

// Username returns the username of the user.
func (s *userV) Username() (string, error) {
	data, err := s.read(s.header.NameOffset, s.header.NameLength)
	if err != nil {
		return "", err
	}

	decoded, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(data)
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}

// EncryptedHashes returns the encrypted LM and NT hashes of the user.
// Note that at this point, the hashes are still encrypted with RC4 or AES.
func (s *userV) EncryptedHashes() ([]byte, []byte, error) {
	if s.header.NtHashLength == 0 {
		return nil, nil, errNoHashInfoFound
	}

	ntHash, err := s.read(s.header.NtHashOffset, s.header.NtHashLength)
	if err != nil {
		return nil, nil, err
	}

	lmHash, err := s.read(s.header.LmHashOffset, s.header.LmHashLength)
	if err != nil {
		return nil, nil, err
	}

	return lmHash, ntHash, nil
}

type userVHeader struct {
	Reserved0            [12]byte
	NameOffset           uint32
	NameLength           uint32
	Reserved1            uint32
	FullNameOffset       uint32
	FullNameLength       uint32
	Reserved2            uint32
	CommentOffset        uint32
	CommentLength        uint32
	Reserved3            uint32
	UserCommentOffset    uint32
	UserCommentLength    uint32
	Reserved4            uint32
	Reserved5            [12]byte
	HomeDirOffset        uint32
	HomeDirLength        uint32
	Reserved6            uint32
	HomeDirConnectOffset uint32
	HomeDirConnectLength uint32
	Reserved7            uint32
	ScriptPathOffset     uint32
	ScriptPathLength     uint32
	Reserved8            uint32
	ProfilePathOffset    uint32
	ProfilePathLength    uint32
	Reserved9            uint32
	WorkstationsOffset   uint32
	WorkstationsLength   uint32
	Reserved10           uint32
	HoursAllowedOffset   uint32
	HoursAllowedLength   uint32
	Reserved11           uint32
	Reserved12           [12]byte
	LmHashOffset         uint32
	LmHashLength         uint32
	Reserved13           uint32
	NtHashOffset         uint32
	NtHashLength         uint32
	Reserved14           uint32
	Reserved15           [24]byte
}
