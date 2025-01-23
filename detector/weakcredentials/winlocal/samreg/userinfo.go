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
	"encoding/hex"
	"errors"
	"slices"
)

// UserInfo contains the information about a user in the SAM hive.
type UserInfo struct {
	rid   string
	userV *userV
	userF *userF
}

// Username returns the username of the user.
func (s *UserInfo) Username() (string, error) {
	return s.userV.Username()
}

// Enabled returns whether the user is enabled or not.
func (s *UserInfo) Enabled() (bool, error) {
	return s.userF.Enabled()
}

func (s *UserInfo) handleRC4Hash(syskey, lmData, ntData, ridBytes []byte) ([]byte, []byte, error) {
	var ntHash, lmHash []byte
	var err error

	if len(ntData) != 20 && len(lmData) != 20 {
		return nil, nil, errNoHashInfoFound
	}

	if len(ntData) == 20 {
		ntHash, err = decryptRC4Hash(ridBytes, syskey, ntData[4:], []byte(NTLMHashConstant))
		if err != nil {
			return nil, nil, err
		}
	}

	if len(lmData) == 20 {
		lmHash, err = decryptRC4Hash(ridBytes, syskey, lmData[4:], []byte(LMHashConstant))
		if err != nil {
			return nil, nil, err
		}
	}

	return lmHash, ntHash, nil
}

func (s *UserInfo) handleAESHash(syskey, lmData, ntData, ridBytes []byte) ([]byte, []byte, error) {
	var ntHash, lmHash []byte
	var err error

	if len(ntData) <= 24 && len(lmData) <= 24 {
		return nil, nil, errNoHashInfoFound
	}

	if len(ntData) > 24 {
		ntHash, err = decryptAESHash(ridBytes, syskey, ntData[24:], ntData[8:24])
		if err != nil {
			return nil, nil, err
		}
	}

	if len(lmData) > 24 {
		lmHash, err = decryptAESHash(ridBytes, syskey, lmData[24:], lmData[8:24])
		if err != nil {
			return nil, nil, err
		}
	}

	return lmHash, ntHash, nil
}

func (s *UserInfo) decryptHashes(syskey, lmData, ntData []byte) ([]byte, []byte, error) {
	ridBytes, err := hex.DecodeString(s.rid)
	if err != nil {
		return nil, nil, err
	}

	// note: reversing the slice to get the right endianness
	slices.Reverse(ridBytes)

	if len(ntData) < 3 {
		return nil, nil, errors.New("failed to decrypt hashes: NT data is too short")
	}

	// If the third-byte is set to 0x1, the hashes are encrypted using RC4.
	if ntData[2] == 0x1 {
		return s.handleRC4Hash(syskey, lmData, ntData, ridBytes)
	}

	return s.handleAESHash(syskey, lmData, ntData, ridBytes)
}

// Hashes returns the LM and NT hashes of the user.
// Note that the syskey is expected to be already derived.
func (s *UserInfo) Hashes(syskey []byte) ([]byte, []byte, error) {
	lmHash, ntHash, err := s.userV.EncryptedHashes()
	if err != nil {
		return nil, nil, err
	}

	return s.decryptHashes(syskey, lmHash, ntHash)
}
