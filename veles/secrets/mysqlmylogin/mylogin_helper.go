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

package mysqlmylogin

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
)

const (
	loginKeyLen = 20
	maxCipher   = 4096
)

// decryptMyLoginCNF decrypts the content of .mylogin.cnf from an io.Reader
//
// .mylogin.cnf file format (MySQL 5.6+):
// - First 4 bytes: unused/reserved (probably for version number)
// - Next 20 bytes: key used to derive the AES key via XOR
// - Rest of the file: repeated for each chunk:
//   - 4 bytes: length of encrypted chunk (little-endian)
//   - n bytes: encrypted chunk
//
// References:
// - MySQL Documentation: https://dev.mysql.com/doc/refman/8.0/en/mysql-config-editor.html
// - Reference implementation: https://ocelot.ca/blog/blog/2015/05/21/decrypt-mylogin-cnf/
// - Reference implementation: https://github.com/PyMySQL/myloginpath
// - MySQL source code: https://github.com/ocelot-inc/ocelotgui/blob/master/readmylogin.c
func decryptMyLoginCNF(reader io.Reader) ([]byte, error) {
	// Read the first 4 bytes (unused/reserved for future version)
	// Reference: "First four bytes are unused, probably reserved for version number"
	var unused [4]byte
	if err := binary.Read(reader, binary.LittleEndian, &unused); err != nil {
		return nil, errors.New("error reading header")
	}

	// Read the key (20 bytes)
	// From the Reference:
	//  "Next twenty bytes are the basis of the key, to be XORed in a loop
	//       until a sixteen-byte key is produced"
	key := make([]byte, loginKeyLen)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, errors.New("error reading key")
	}

	// Derive the 16-byte AES key via cyclic XOR
	// Reference: XOR of the 20 bytes into a 16-byte buffer
	aesKey := make([]byte, aes.BlockSize)
	for i := range loginKeyLen {
		aesKey[i%aes.BlockSize] ^= key[i]
	}

	// Initialize the AES cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, errors.New("error initializing AES")
	}

	var plaintext []byte

	// Read and decrypt chunks
	// Reference:
	//       "The rest of the file is, repeated as necessary:
	//       four bytes = length of following cipher chunk, little-endian
	//       n bytes = cipher chunk"
	for {
		// Read chunk length (4 bytes, little-endian)
		var chunkLen uint32
		if err := binary.Read(reader, binary.LittleEndian, &chunkLen); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, errors.New("error reading chunk length")
		}

		if chunkLen > maxCipher {
			return nil, errors.New("chunk too large")
		}

		// Read the encrypted chunk
		cipherChunk := make([]byte, chunkLen)
		if _, err := io.ReadFull(reader, cipherChunk); err != nil {
			return nil, errors.New("error reading encrypted chunk")
		}

		// Decrypt the chunk using AES-128-ECB
		// Reference: "Encryption is AES 128-bit ecb"
		// Reference: MySQL default block_encryption_mode is aes-128-ecb
		decryptedChunk, err := decryptAES128ECB(cipherChunk, block)
		if err != nil {
			return nil, errors.New("error decrypting chunk")
		}

		// Remove padding from the chunk
		// Reference:
		//       "Chunk lengths are always a multiple of 16 bytes (128 bits).
		//       Therefore there may be padding. We assume that any trailing
		//       byte containing a value less than '\n' is a padding byte."
		decryptedChunk = removePaddingBytes(decryptedChunk)

		plaintext = append(plaintext, decryptedChunk...)
	}

	return plaintext, nil
}

// removePaddingBytes removes padding bytes from the plaintext
//
// From Reference:
// "We assume that any trailing byte containing a value less than '\n'
//
//	is a padding byte"
func removePaddingBytes(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	pad := int(data[len(data)-1]) // last byte indicates padding length
	if pad <= 0 || pad > aes.BlockSize {
		// Not valid padding (or no padding). Return as-is.
		return data
	}

	// Ensure the last 'pad' bytes all equal 'pad'
	if pad > len(data) {
		return data
	}
	for i := len(data) - pad; i < len(data); i++ {
		if int(data[i]) != pad {
			// Invalid padding; return original
			return data
		}
	}

	return data[:len(data)-pad]
}

// decryptAES128ECB decrypts using AES-128 in ECB mode
//
// ECB (Electronic Codebook) mode decrypts each block independently.
// Note: ECB is not secure for real sensitive data, but MySQL uses .mylogin.cnf
// only for obfuscation, not for true security.
//
// From the Reference: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB
func decryptAES128ECB(ciphertext []byte, block cipher.Block) ([]byte, error) {
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}

	plaintext := make([]byte, len(ciphertext))

	// ECB mode: decrypt each 16-byte block independently
	for i := 0; i < len(ciphertext); i += aes.BlockSize {
		block.Decrypt(plaintext[i:i+aes.BlockSize], ciphertext[i:i+aes.BlockSize])
	}

	return plaintext, nil
}
