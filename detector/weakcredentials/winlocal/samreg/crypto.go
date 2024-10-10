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
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"fmt"
	"slices"
)

const (
	// LMHashConstant is used to decrypt LM hashes when RC4 is used.
	LMHashConstant = "LMPASSWORD\x00"
	// NTLMHashConstant is used to decrypt NTLM hashes when RC4 is used.
	NTLMHashConstant = "NTPASSWORD\x00"
)

var (
	errInvalidRIDSize = fmt.Errorf("RID cannot be derived: is not 4 bytes")
)

func transformRID(key []byte) []byte {
	var outputKey []byte
	outputKey = append(outputKey, key[0]>>0x1)
	outputKey = append(outputKey, ((key[0]&0x01)<<6)|(key[1]>>2))
	outputKey = append(outputKey, ((key[1]&0x03)<<5)|(key[2]>>3))
	outputKey = append(outputKey, ((key[2]&0x07)<<4)|(key[3]>>4))
	outputKey = append(outputKey, ((key[3]&0x0F)<<3)|(key[4]>>5))
	outputKey = append(outputKey, ((key[4]&0x1F)<<2)|(key[5]>>6))
	outputKey = append(outputKey, ((key[5]&0x3F)<<1)|(key[6]>>7))
	outputKey = append(outputKey, key[6]&0x7F)

	for i := 0; i < 8; i++ {
		outputKey[i] = (outputKey[i] << 1) & 0xfe
	}

	return outputKey
}

func deriveRID(rid []byte) ([]byte, []byte, error) {
	if len(rid) != 4 {
		return nil, nil, errInvalidRIDSize
	}

	rid1 := []byte{rid[0], rid[1], rid[2], rid[3], rid[0], rid[1], rid[2]}
	rid2 := []byte{rid[3], rid[0], rid[1], rid[2], rid[3], rid[0], rid[1]}
	return transformRID(rid1), transformRID(rid2), nil
}

func commonHashDecryption(rid []byte, key []byte, hash []byte) ([]byte, error) {
	key1, key2, err := deriveRID(rid)
	if err != nil {
		return nil, err
	}

	block1, err := des.NewCipher(key1)
	if err != nil {
		return nil, err
	}

	block2, err := des.NewCipher(key2)
	if err != nil {
		return nil, err
	}

	decryptedHash := make([]byte, 16)
	block1.Decrypt(decryptedHash[:8], key[:8])
	block2.Decrypt(decryptedHash[8:], key[8:])
	return decryptedHash, nil
}

// decryptRC4Hash decrypts the RC4 encrypted user's hash back to LM/NTLM format using the derived
// syskey.
func decryptRC4Hash(rid []byte, syskey, hash []byte, hashConstant []byte) ([]byte, error) {
	rc4Key := md5.Sum(slices.Concat(syskey, rid, hashConstant))
	c, err := rc4.NewCipher(rc4Key[:])
	if err != nil {
		return nil, err
	}

	key := make([]byte, 16)
	c.XORKeyStream(key, hash)
	return commonHashDecryption(rid, key[:16], hash)
}

// decryptAESHash decrypts the AES encrypted user's hash back to LM/NTLM format using the derived
// syskey.
func decryptAESHash(rid []byte, syskey, hash []byte, salt []byte) ([]byte, error) {
	if len(hash) == 0 {
		return nil, nil
	}

	block, err := aes.NewCipher(syskey)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, salt)
	key := make([]byte, 32)
	mode.CryptBlocks(key, hash)
	return commonHashDecryption(rid, key, hash)
}
