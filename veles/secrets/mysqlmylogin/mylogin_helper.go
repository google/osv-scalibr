package mysqlmylogin

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
)

const (
	// Buffer at the beginning of the login path file
	unusedBufferLength = 4
	// The length of the key stored in the file
	loginKeyLength = 20
	// Number of bytes used to store the length of ciphertext
	cipherStoreLength = 4
)

// Read reads and decrypts the contents of the login path file
func Read(buf io.Reader) (string, error) {
	plaintext, err := readEncryptedFile(buf)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// readKey reads the key from the login path file header
//
// According to the .mylogin.cnf file format specification:
// Reference: https://ocelot.ca/blog/blog/2015/05/21/decrypt-mylogin-cnf/
//
// File structure:
//   - First 4 bytes: unused (probably reserved for version number)
//   - Next 20 bytes: the basis of the encryption key (to be XORed in a loop
//     until a 16-byte AES key is produced)
//   - Remaining bytes: encrypted data chunks, each prefixed by its length
//
// The file uses AES 128-bit ECB encryption for obfuscation (not true security,
// as the key is stored in the file itself).
// Official MySQL documentation: https://dev.mysql.com/doc/refman/8.4/en/mysql-config-editor.html
func readKey(fp io.Reader) ([]byte, error) {
	// Move past the unused buffer
	buffer := make([]byte, unusedBufferLength)
	n, err := io.ReadFull(fp, buffer)
	if err != nil || n != unusedBufferLength {
		return nil, errors.New("login path file is blank or incomplete")
	}

	// Read the login key
	key := make([]byte, loginKeyLength)
	n, err = io.ReadFull(fp, key)
	if err != nil || n != loginKeyLength {
		return nil, errors.New("failed to read login key")
	}

	// Convert the 20-byte key into a 16-byte AES key using XOR
	// Each byte of the 20-byte key is XORed with the corresponding position
	return createKey(key), nil
}

// createKey creates the AES key from the login path file header
func createKey(key []byte) []byte {
	rkey := make([]byte, 16)
	for i := range key {
		rkey[i%16] ^= key[i]
	}
	return rkey
}

// readEncryptedFile decrypts a file
func readEncryptedFile(f io.Reader) ([]byte, error) {
	key, err := readKey(f)
	if err != nil {
		return nil, err
	}

	// Create a new AES cipher block using the extracted key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("failed to create AES cipher")
	}

	var plaintext bytes.Buffer

	// Start loop to read all encrypted lines from the file
	for {
		// Read the length of the line
		lengthBuffer := make([]byte, cipherStoreLength)
		// Read exactly cipherStoreLength bytes into the buffer
		n, err := io.ReadFull(f, lengthBuffer)
		if n < cipherStoreLength {
			break
		}

		if err != nil && !errors.Is(err, io.EOF) {
			return nil, errors.New("failed to read length")
		}

		// Convert the 4-byte buffer to a 32-bit integer (little-endian format)
		// This tells us how many bytes the encrypted line contains
		lineLength := int32(binary.LittleEndian.Uint32(lengthBuffer))

		line, err := readLine(f, int(lineLength), block)
		if err != nil {
			return nil, err
		}

		plaintext.Write(line)
	}

	return plaintext.Bytes(), nil
}

// readLine reads a line of specified length and decrypts it
func readLine(f io.Reader, length int, block cipher.Block) ([]byte, error) {
	line := make([]byte, length)
	n, err := io.ReadFull(f, line)
	if err != nil || n != length {
		return nil, errors.New("failed to read line")
	}

	// Decrypt using ECB mode (decrypt each block independently)
	decrypted := make([]byte, len(line))
	blockSize := block.BlockSize()

	// Loop through the encrypted data in chunks of blockSize
	// AES ECB mode decrypts each block independently
	for i := 0; i < len(line); i += blockSize {
		block.Decrypt(decrypted[i:i+blockSize], line[i:i+blockSize])
	}

	// Remove PKCS#7 padding from the decrypted data and return
	return removePad(decrypted)
}

// removePad removes PKCS#7 padding from the line
func removePad(line []byte) ([]byte, error) {
	if len(line) == 0 {
		return nil, errors.New("empty line")
	}

	// Get the last byte of the decrypted data
	// In PKCS#7, this byte tells us how many padding bytes were added
	// For example, if the last byte is 0x05, there are 5 padding bytes total
	padLength := int(line[len(line)-1])

	// Validate the padding length
	// The number of padding bytes cannot exceed the total length of the data
	// If it does, the data is corrupted or wasn't properly encrypted
	if padLength > len(line) {
		return nil, errors.New("invalid pad length")
	}

	// Remove the padding by returning everything except the last padLength bytes
	return line[:len(line)-padLength], nil
}
