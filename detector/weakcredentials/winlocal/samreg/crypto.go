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
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"errors"
	"slices"
)

/*
** Note: This file contains the code to perform the final step of decrypting the user's hashes.
**
** You can read more about hash encryption in the following article:
** https://web.archive.org/web/20190717124313/http://www.beginningtoseethelight.org/ntsecurity/index.htm#D3BC3F5643A17823
**
** The hashes are encrypted several times with different encryption algorithms and keys.
** First, the hashes can be encrypted with RC4 or AES-256.
**   - For RC4, the key is the MD5 hash of the syskey, the RID and statically defined constants
**     (different for NTLM or LM).
**   - For AES-256, the key is the syskey and the IV is found in the UserV structure directly.
**
** Whether RC4 or AES-256 is to be used depends on a combination of the current OS version, the time
** the hash were generated and the current OS configuration. But the hash data stored in the UserV
** structure contains bits indicating which encryption algorithm was used.
**
** Once the first decryption has been performed, the hash is always encrypted with a final layer of
** DES. The encrypted is split in two halves and each half is decrypted with a different key.
** The two keys are derived from the user's RID. They are derived from a set of statically
** defined permutations and bitwise operations.
 */

const (
	// LMHashConstant is used to decrypt LM hashes when RC4 is used.
	LMHashConstant = "LMPASSWORD\x00"
	// NTLMHashConstant is used to decrypt NTLM hashes when RC4 is used.
	NTLMHashConstant = "NTPASSWORD\x00"
)

var (
	errInvalidRIDSize = errors.New("RID cannot be derived: is not 4 bytes")
)

// transformRID performs a set of bitwise operations on the provided key to derive one of the two
// 8-byte keys that will be used in the final step of hash decryption (DES).
// These bitwise operations are hardcoded on the Windows side, so we do the same here.
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

	for i := range 8 {
		outputKey[i] = (outputKey[i] << 1) & 0xfe
	}

	return outputKey
}

// deriveRID derives two 8-byte keys from the provided RID. It performs a set of predefined
// circular permutations on the RID before using transformRID to perform bitwise operations that
// will result in the final keys.
func deriveRID(rid []byte) ([]byte, []byte, error) {
	if len(rid) != 4 {
		return nil, nil, errInvalidRIDSize
	}

	rid1 := []byte{rid[0], rid[1], rid[2], rid[3], rid[0], rid[1], rid[2]}
	rid2 := []byte{rid[3], rid[0], rid[1], rid[2], rid[3], rid[0], rid[1]}
	return transformRID(rid1), transformRID(rid2), nil
}

// Whichever encryption algorithm is used, the last round of decryption is always DES. It involves:
//   - Taking the RID of the user and deriving it into two 8-byte DES keys
//   - Each of these two keys is then used to decrypt a half of the encrypted hash
func decryptDES(rid []byte, encryptedHash []byte) ([]byte, error) {
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
	block1.Decrypt(decryptedHash[:8], encryptedHash[:8])
	block2.Decrypt(decryptedHash[8:], encryptedHash[8:])
	return decryptedHash, nil
}

// decryptRC4Hash decrypts the RC4 encrypted user's hash back to LM/NTLM format using the derived
// syskey. Note that the syskey is expected to be already derived.
func decryptRC4Hash(rid []byte, syskey, hash []byte, hashConstant []byte) ([]byte, error) {
	rc4Key := md5.Sum(slices.Concat(syskey, rid, hashConstant))
	c, err := rc4.NewCipher(rc4Key[:])
	if err != nil {
		return nil, err
	}

	rc4Decrypted := make([]byte, 16)
	c.XORKeyStream(rc4Decrypted, hash)
	return decryptDES(rid, rc4Decrypted[:16])
}

// decryptAESHash decrypts the AES encrypted user's hash back to LM/NTLM format using the derived
// syskey. Note that the syskey is expected to be already derived.
func decryptAESHash(rid []byte, syskey, hash []byte, iv []byte) ([]byte, error) {
	if len(hash) == 0 {
		return nil, nil
	}

	if len(hash)%aes.BlockSize != 0 {
		return nil, errors.New("hash length not aligned with AES block size")
	}

	block, err := aes.NewCipher(syskey)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	aesDecrypted := make([]byte, 32)
	mode.CryptBlocks(aesDecrypted, hash)
	return decryptDES(rid, aesDecrypted)
}
