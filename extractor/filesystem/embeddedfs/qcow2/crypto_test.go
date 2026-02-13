package qcow2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
)

func TestDiffuse(t *testing.T) {
	src := make([]byte, 64)
	for i := range src {
		src[i] = byte(i)
	}
	dst := make([]byte, 64)

	if err := diffuse(src, dst, hashSHA256); err != nil {
		t.Fatalf("diffuse failed: %v", err)
	}

	// Determinism check
	dst2 := make([]byte, 64)
	if err := diffuse(src, dst2, hashSHA256); err != nil {
		t.Fatalf("diffuse failed: %v", err)
	}

	if !bytes.Equal(dst, dst2) {
		t.Fatalf("diffuse is not deterministic")
	}
}

func TestDiffuseLengthMismatch(t *testing.T) {
	err := diffuse([]byte{1, 2}, []byte{1}, hashSHA1)
	if err == nil {
		t.Fatalf("expected error for length mismatch")
	}
}

func TestAFMergeSingleStripe(t *testing.T) {
	key := []byte{1, 2, 3, 4}
	out, err := afMerge(key, 4, 1, hashSHA1)
	if err != nil {
		t.Fatalf("AFmerge failed: %v", err)
	}
	if !bytes.Equal(out, key) {
		t.Fatalf("AFmerge single stripe mismatch")
	}
}

func TestAFMergeMultipleStripes(t *testing.T) {
	masterLen := 16
	stripes := 4
	split := make([]byte, masterLen*stripes)
	for i := range split {
		split[i] = byte(i)
	}

	out, err := afMerge(split, masterLen, stripes, hashSHA256)
	if err != nil {
		t.Fatalf("AFmerge failed: %v", err)
	}

	if len(out) != masterLen {
		t.Fatalf("unexpected output length: %d", len(out))
	}
}

func TestAFMergeInvalidInput(t *testing.T) {
	_, err := afMerge([]byte{1, 2}, 16, 2, hashSHA1)
	if err == nil {
		t.Fatalf("expected error for invalid input length")
	}
}

func TestParseCipherMode(t *testing.T) {
	tests := []struct {
		in       string
		wantErr  bool
		wantMode cipherMode
		wantIV   ivGen
		wantHash hashAlgorithm
	}{
		{"xts-plain64", false, cipherModeXTS, ivGenPlain64, ""},
		{"cbc-plain", false, cipherModeCBC, ivGenPlain, ""},
		{"cbc-essiv:sha256", false, cipherModeCBC, ivGenESSIV, hashSHA256},
		{"cbc-essiv", true, "", "", ""},
		{"foo-bar", true, "", "", ""},
	}

	for _, tt := range tests {
		mode, ivg, hash, err := parseCipherMode(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("expected error for %q", tt.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", tt.in, err)
		}
		if mode != tt.wantMode || ivg != tt.wantIV || hash != tt.wantHash {
			t.Fatalf("parseCipherMode(%q) mismatch", tt.in)
		}
	}
}

func TestLegacyAESDecrypt(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)

	cfg := &legacyAESConfig{cipher: block}

	plaintext := make([]byte, sectorSize)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	// Encrypt first
	ciphertext := make([]byte, sectorSize)
	iv := make([]byte, block.BlockSize())
	binary.LittleEndian.PutUint64(iv, 0)
	encr := cipher.NewCBCEncrypter(block, iv)
	encr.CryptBlocks(ciphertext, plaintext)

	out, err := cfg.Decrypt(ciphertext, 0)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("legacyAES decrypt mismatch")
	}
}

func TestLUKSDecryptCBCPlain(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)

	cfg := &luksConfig{
		masterKey:  key,
		cipherName: "aes",
		cipherMode: cipherModeCBC,
		ivGen:      ivGenPlain64,
		sectorSize: sectorSize,
	}

	plaintext := make([]byte, sectorSize)
	for i := range plaintext {
		plaintext[i] = byte(255 - i)
	}

	iv := make([]byte, block.BlockSize())
	binary.LittleEndian.PutUint64(iv, 0)
	ciphertext := make([]byte, sectorSize)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)

	out, err := cfg.Decrypt(ciphertext, 0)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("luks CBC decrypt mismatch")
	}
}

func TestSetupEncryption_Unencrypted(t *testing.T) {
	h := &header{CryptMethod: 0}

	cfg, err := setupEncryption(h, nil, "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil cryptoConfig for unencrypted image")
	}
}

func TestSetupEncryption_PasswordRequired(t *testing.T) {
	h := &header{CryptMethod: 1}

	_, err := setupEncryption(h, nil, "", nil)
	if err == nil {
		t.Fatalf("expected password error")
	}
}

func TestSetupEncryption_LegacyAES(t *testing.T) {
	h := &header{CryptMethod: 1}

	cfg, err := setupEncryption(h, nil, "password", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatalf("expected legacyAESConfig")
	}
}

func TestInitESSIV_AES_SHA256(t *testing.T) {
	key := []byte("this is a test key")

	c, err := initESSIV(key, hashSHA256, "aes")
	if err != nil {
		t.Fatalf("initESSIV failed: %v", err)
	}
	if c == nil {
		t.Fatalf("expected non-nil ESSIV cipher")
	}

	// AES block size sanity check
	if c.BlockSize() != aes.BlockSize {
		t.Fatalf("unexpected block size: %d", c.BlockSize())
	}
}

func TestInitESSIV_InvalidHash(t *testing.T) {
	_, err := initESSIV([]byte("key"), "md5", "aes")
	if err == nil {
		t.Fatalf("expected error for unsupported hash")
	}
}

func TestInitESSIV_InvalidCipher(t *testing.T) {
	_, err := initESSIV([]byte("key"), hashSHA1, "blowfish")
	if err == nil {
		t.Fatalf("expected error for unsupported cipher")
	}
}

func TestLUKSDecryptCBCESSIV(t *testing.T) {
	key := make([]byte, 16) // AES-128
	for i := range key {
		key[i] = byte(i)
	}

	essiv, err := initESSIV(key, hashSHA256, "aes")
	if err != nil {
		t.Fatalf("initESSIV failed: %v", err)
	}

	cfg := &luksConfig{
		masterKey:   key,
		cipherName:  "aes",
		cipherMode:  cipherModeCBC,
		ivGen:       ivGenESSIV,
		ivHash:      hashSHA256,
		sectorSize:  sectorSize,
		essivCipher: essiv,
	}

	plaintext := make([]byte, sectorSize)
	for i := range plaintext {
		plaintext[i] = byte(100 + i)
	}

	// Encrypt manually using ESSIV IV
	block, _ := aes.NewCipher(key)
	ivgen := &ESSIVGen{cipher: essiv}
	iv, err := ivgen.Calculate(0, block.BlockSize())
	if err != nil {
		t.Fatalf("IV generation failed: %v", err)
	}

	ciphertext := make([]byte, sectorSize)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)

	out, err := cfg.Decrypt(ciphertext, 0)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("ESSIV CBC decrypt mismatch")
	}
}
