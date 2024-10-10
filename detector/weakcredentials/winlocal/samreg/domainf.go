// Copyright 2024 Google LLC
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
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"slices"
)

const (
	fDomStructKeyOffset = 0x68
)

var (
	errDomainFTooShort = fmt.Errorf("domain F structure is too short")
	errInvalidChecksum = fmt.Errorf("error while deriving syskey: invalid checksum")
	errInvalidRevision = fmt.Errorf("error while deriving syskey: invalid revision")
)

// DomainF is a lazy-parsed domain F structure containing the domain's information in the
// SAM hive.
// Very important: Do not confuse the SAMUSerF and SAMDomainF structures, the first one refers to
// each user's information (is account active, locked, when was password changed, etc.) while the
// second one refers to the domain's information (password policy, portion of the syskey).
// See https://web.archive.org/web/20190717124313/http://www.beginningtoseethelight.org/ntsecurity/index.htm#BB4F910C0FFA1E43
// for more information about the F domain structure.
type DomainF struct {
	buffer []byte
}

// NewDomainF creates a new lazy-parsed domain F structure from the SAM hive.
func NewDomainF(data []byte) *DomainF {
	return &DomainF{
		buffer: data,
	}
}

// DeriveSyskey derives the syskey (aka bootkey).
func (s *DomainF) DeriveSyskey(origSyskey []byte) ([]byte, error) {
	if len(s.buffer) < fDomStructKeyOffset+1 {
		return nil, errDomainFTooShort
	}

	fDomKeyPart := s.buffer[fDomStructKeyOffset:]

	// Key is encrypted with RC4.
	if fDomKeyPart[0] == 1 {
		qwerty := []byte("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00")
		digits := []byte("0123456789012345678901234567890123456789\x00")

		keyData := samSyskeyData{}
		if err := binary.Read(bytes.NewBuffer(fDomKeyPart), binary.LittleEndian, &keyData); err != nil {
			return nil, err
		}

		rc4key := md5.Sum(slices.Concat(keyData.Salt[:], qwerty, origSyskey, digits))
		cipher, err := rc4.NewCipher(rc4key[:])
		if err != nil {
			return nil, err
		}

		derivedKey := make([]byte, 32)
		cipher.XORKeyStream(derivedKey, slices.Concat(keyData.Key[:], keyData.Checksum[:]))
		checksum := md5.Sum(slices.Concat(derivedKey[:16], digits, derivedKey[:16], qwerty))
		if slices.Compare(checksum[:], derivedKey[16:]) != 0 {
			return nil, errInvalidChecksum
		}

		return derivedKey[:16], nil
	}

	// The key uses AES.
	if fDomKeyPart[0] == 2 {
		keyData := samSyskeyDataAES{}
		if err := binary.Read(bytes.NewBuffer(fDomKeyPart), binary.LittleEndian, &keyData); err != nil {
			return nil, err
		}

		if len(fDomKeyPart) < int(keyData.DataLength)+0x20 {
			return nil, errDomainFTooShort
		}

		data := fDomKeyPart[0x20 : 0x20+int(keyData.DataLength)]
		block, err := aes.NewCipher(origSyskey)
		if err != nil {
			return nil, err
		}

		mode := cipher.NewCBCDecrypter(block, keyData.Salt[:])
		derivedKey := make([]byte, keyData.DataLength)
		mode.CryptBlocks(derivedKey, data)
		return derivedKey[:16], nil
	}

	return nil, errInvalidRevision
}

type samSyskeyData struct {
	Revision uint32
	Length   uint32
	Salt     [16]byte
	Key      [16]byte
	Checksum [16]byte
}

type samSyskeyDataAES struct {
	Revision       uint32
	Length         uint32
	ChecksumLength uint32
	DataLength     uint32
	Salt           [16]byte
}
