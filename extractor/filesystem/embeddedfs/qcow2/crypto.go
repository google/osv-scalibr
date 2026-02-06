package qcow2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

	"github.com/aead/serpent"
	"github.com/emmansun/gmsm/sm4"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/xts"
)

// cipherMode, ivGen, and hashAlgorithm types for cipher mode parsing
type cipherMode string
type ivGen string
type hashAlgorithm string

const (
	luksMagic                   = "LUKS\xba\xbe"
	cryptoHeaderType            = 0x0537be77
	luksDigestSize              = 20
	luksKeyEnabled              = 0x00AC71F3
	cipherModeXTS    cipherMode = "xts"
	cipherModeCBC    cipherMode = "cbc"

	ivGenPlain   ivGen         = "plain"
	ivGenPlain64 ivGen         = "plain64"
	ivGenESSIV   ivGen         = "essiv"
	hashSHA1     hashAlgorithm = "sha1"
	hashSHA256   hashAlgorithm = "sha256"
)

// luksHeader represents the LUKS1 header (592 bytes)
type luksHeader struct {
	Magic              [6]byte
	Version            uint16
	CipherName         [32]byte // also called cipher_algo in block-luks.c
	CipherMode         [32]byte
	HashSpec           [32]byte // also called hash_algo in block-luks.c, used in pbkdf2
	PayloadOffset      uint32
	KeyBytes           uint32 // also called master_key_len in block-luks.c
	MKDigest           [20]byte
	MKDigestSalt       [32]byte
	MKDigestIterations uint32
	UUID               [40]byte
	KeySlots           [8]luksKeySlot
}

// luksKeySlot represents a LUKS key slot
type luksKeySlot struct {
	Active             uint32
	PasswordIterations uint32
	PasswordSalt       [32]byte
	KeyMaterialOffset  uint32
	Stripes            uint32
}

// cryptoConfig interface for encryption
type cryptoConfig interface {
	Decrypt(data []byte, guestOffset uint64) ([]byte, error)
	IsEncryptedOffset(offset uint64) bool
}

// legacyAESConfig for legacy AES encryption
type legacyAESConfig struct {
	cipher cipher.Block
}

// luksConfig for LUKS encryption
type luksConfig struct {
	masterKey      []byte
	cipherName     string
	cipherMode     cipherMode
	ivGen          ivGen
	ivHash         hashAlgorithm
	hashSpec       hashAlgorithm
	keyBytes       uint32
	sectorSize     uint64
	encryptedStart uint64
	dataCipher     *xts.Cipher  // Used for XTS mode
	essivCipher    cipher.Block // Used for ESSIV in CBC mode
}

// luksCipherNameLookup validates cipher name
func luksCipherNameLookup(cipherName string) (string, error) {
	if strings.HasPrefix(strings.ToLower(cipherName), "aes") {
		return "aes", nil
	}
	if strings.HasPrefix(strings.ToLower(cipherName), "serpent") {
		return "serpent", nil
	}
	if strings.HasPrefix(strings.ToLower(cipherName), "sm4") {
		return "sm4", nil
	}
	return "", fmt.Errorf("unsupported cipher algorithm: %s", cipherName)
}

// luksHashNameLookup maps LUKS hash names to Go hash functions
func luksHashNameLookup(hashName hashAlgorithm) (func() hash.Hash, int, error) {
	switch hashName {
	case hashSHA1:
		return sha1.New, sha1.Size, nil
	case hashSHA256:
		return sha256.New, sha256.Size, nil
	default:
		return nil, 0, fmt.Errorf("unsupported hash algorithm: %s", hashName)
	}
}

// initESSIV initializes ESSIV cipher with a salt derived from the key
func initESSIV(key []byte, ivHash hashAlgorithm, normalizedCipher string) (cipher.Block, error) {
	hashFunc, digestSize, err := luksHashNameLookup(ivHash)
	if err != nil {
		return nil, err
	}
	// dm-crypt quirk: ESSIV cipher key length matches hash digest length
	keyLen := digestSize
	salt := make([]byte, keyLen)
	h := hashFunc()
	h.Write(key)
	copy(salt, h.Sum(nil)[:min(digestSize, keyLen)])
	switch normalizedCipher {
	case "aes":
		essivCipher, err := aes.NewCipher(salt)
		if err != nil {
			return nil, fmt.Errorf("failed to create ESSIV cipher: %w", err)
		}
		return essivCipher, nil
	case "serpent":
		essivCipher, err := serpent.NewCipher(salt)
		if err != nil {
			return nil, fmt.Errorf("failed to create ESSIV cipher: %w", err)
		}
		return essivCipher, nil
	case "sm4":
		essivCipher, err := sm4.NewCipher(salt)
		if err != nil {
			return nil, fmt.Errorf("failed to create ESSIV cipher: %w", err)
		}
		return essivCipher, nil
	}
	return nil, fmt.Errorf("unknown ESSIV cipher: %s", normalizedCipher)
}

// initXTS initializes XTS cipher with a key
func initXTS(key []byte, normalizedCipher string) (*xts.Cipher, error) {
	var cipherFunc func([]byte) (cipher.Block, error)
	switch normalizedCipher {
	case "aes":
		cipherFunc = aes.NewCipher
	case "serpent":
		cipherFunc = serpent.NewCipher
	case "sm4":
		cipherFunc = sm4.NewCipher
	default:
		return nil, fmt.Errorf("unknown XTS cipher: %s", normalizedCipher)
	}
	tmpCipher, err := xts.NewCipher(cipherFunc, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create XTS cipher: %w", err)
	}
	return tmpCipher, nil
}

// diffuse implements cryptsetup’s diffuse() from af.c
func diffuse(src []byte, dst []byte, hashName hashAlgorithm) error {
	if len(src) != len(dst) {
		return errors.New("diffuse: src and dst length mismatch")
	}
	hashCtor, digestSize, err := luksHashNameLookup(hashName)
	if err != nil {
		return err
	}
	size := len(src)
	blocks := size / digestSize
	rem := size % digestSize

	for i := range blocks {
		h := hashCtor()
		var ivBytes [4]byte
		binary.BigEndian.PutUint32(ivBytes[:], uint32(i))
		h.Write(ivBytes[:])
		h.Write(src[i*digestSize : (i+1)*digestSize])
		sum := h.Sum(nil)
		copy(dst[i*digestSize:(i+1)*digestSize], sum[:digestSize])
	}
	if rem > 0 {
		i := blocks
		h := hashCtor()
		var ivBytes [4]byte
		binary.BigEndian.PutUint32(ivBytes[:], uint32(i))
		h.Write(ivBytes[:])
		h.Write(src[i*digestSize : i*digestSize+rem])
		sum := h.Sum(nil)
		copy(dst[i*digestSize:], sum[:rem])
	}
	return nil
}

// afMerge implements cryptsetup’s AF_merge
func afMerge(split []byte, masterKeyLen int, stripes int, hashName hashAlgorithm) ([]byte, error) {
	if masterKeyLen <= 0 || stripes <= 0 {
		return nil, errors.New("invalid masterKeyLen or stripes")
	}
	if len(split) != masterKeyLen*stripes {
		return nil, fmt.Errorf("AFmerge failed: split length %d does not match masterKeyLen %d * stripes %d", len(split), masterKeyLen, stripes)
	}
	if stripes == 1 {
		out := make([]byte, masterKeyLen)
		copy(out, split[:masterKeyLen])
		return out, nil
	}

	bufblock := make([]byte, masterKeyLen)
	tmp := make([]byte, masterKeyLen)

	for s := range stripes - 1 {
		stripe := split[s*masterKeyLen : (s+1)*masterKeyLen]
		for i := range masterKeyLen {
			bufblock[i] ^= stripe[i]
		}
		if err := diffuse(bufblock, tmp, hashName); err != nil {
			return nil, fmt.Errorf("AFmerge failed: diffuse error: %w", err)
		}
		copy(bufblock, tmp)
	}

	last := split[(stripes-1)*masterKeyLen : stripes*masterKeyLen]
	out := make([]byte, masterKeyLen)
	for i := range masterKeyLen {
		out[i] = last[i] ^ bufblock[i]
	}
	return out, nil
}

// getIVGen returns the appropriate IV generator based on luksConfig
func (c *luksConfig) getIVGen() (IVGenAlgorithm, error) {
	switch c.ivGen {
	case ivGenPlain:
		return &PlainIVGen{}, nil
	case ivGenPlain64:
		return &Plain64IVGen{}, nil
	case ivGenESSIV:
		if c.essivCipher == nil {
			return nil, errors.New("ESSIV cipher not initialized")
		}
		return &ESSIVGen{cipher: c.essivCipher}, nil
	default:
		return nil, fmt.Errorf("unsupported IV generator: %s", c.ivGen)
	}
}

// decryptData decrypts data using the configured cipher and IV generator
func (c *luksConfig) decryptData(data []byte, guestOffset uint64) ([]byte, error) {
	if len(data)%int(c.sectorSize) != 0 {
		return nil, fmt.Errorf("data size %d not sector-aligned", len(data))
	}
	result := make([]byte, len(data))
	ivgen, err := c.getIVGen()
	if err != nil {
		return nil, err
	}
	var blockCipher cipher.Block
	if c.cipherMode != cipherModeXTS {
		switch c.cipherName {
		case "aes":
			blockCipher, err = aes.NewCipher(c.masterKey)
		case "serpent":
			blockCipher, err = serpent.NewCipher(c.masterKey)
		case "sm4":
			blockCipher, err = sm4.NewCipher(c.masterKey)
		default:
			return nil, fmt.Errorf("unsupported cipher: %s", c.cipherName)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to create cipher: %w", err)
		}
	}
	for i := 0; i < len(data); i += int(c.sectorSize) {
		sectorNum := guestOffset/c.sectorSize + uint64(i/int(c.sectorSize))
		if c.cipherMode == cipherModeXTS {
			if c.dataCipher == nil {
				return nil, errors.New("XTS cipher not initialized")
			}
			iv, err := ivgen.Calculate(sectorNum, 16)
			if err != nil {
				return nil, fmt.Errorf("failed to generate XTS tweak: %w", err)
			}
			// XTS uses the IV as a tweak, applied per sector
			c.dataCipher.Decrypt(result[i:i+int(c.sectorSize)], data[i:i+int(c.sectorSize)], binary.LittleEndian.Uint64(iv[:8]))
		} else if c.cipherMode == cipherModeCBC {
			iv, err := ivgen.Calculate(sectorNum, blockCipher.BlockSize())
			if err != nil {
				return nil, fmt.Errorf("failed to generate CBC IV: %w", err)
			}
			decrypter := cipher.NewCBCDecrypter(blockCipher, iv)
			decrypter.CryptBlocks(result[i:i+int(c.sectorSize)], data[i:i+int(c.sectorSize)])
		} else {
			return nil, fmt.Errorf("unsupported cipher mode: %s", c.cipherMode)
		}
	}
	return result, nil
}

func (c *luksConfig) Decrypt(data []byte, guestOffset uint64) ([]byte, error) {
	return c.decryptData(data, guestOffset)
}

func (c *luksConfig) IsEncryptedOffset(offset uint64) bool {
	return offset >= c.encryptedStart
}

func (c *legacyAESConfig) Decrypt(data []byte, guestOffset uint64) ([]byte, error) {
	if len(data)%sectorSize != 0 {
		return nil, fmt.Errorf("data size %d not sector-aligned", len(data))
	}
	result := make([]byte, len(data))
	for i := 0; i < len(data); i += sectorSize {
		sectorNum := guestOffset/sectorSize + uint64(i/sectorSize)
		iv := make([]byte, c.cipher.BlockSize())
		binary.LittleEndian.PutUint64(iv, sectorNum)
		decrypter := cipher.NewCBCDecrypter(c.cipher, iv)
		decrypter.CryptBlocks(result[i:i+sectorSize], data[i:i+sectorSize])
	}
	return result, nil
}

func (c *legacyAESConfig) IsEncryptedOffset(offset uint64) bool {
	return true
}

// setupEncryption configures LUKS encryption
func setupEncryption(header *header, extensions []headerExtension, password string, reader io.Reader) (cryptoConfig, error) {
	if header.CryptMethod == 0 {
		return nil, nil
	}
	if password == "" {
		return nil, errors.New("password required for encrypted image")
	}

	if header.CryptMethod == 1 {
		key := make([]byte, 16)
		copy(key, []byte(password))
		blockCipher, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %w", err)
		}
		return &legacyAESConfig{cipher: blockCipher}, nil
	}

	var cryptoExt *headerExtension
	for _, ext := range extensions {
		if ext.Type == cryptoHeaderType {
			cryptoExt = &ext
			break
		}
	}
	if cryptoExt == nil {
		return nil, errors.New("LUKS crypto header extension missing")
	}

	var extData struct {
		Offset uint64
		Length uint64
	}
	if err := binary.Read(bytes.NewReader(cryptoExt.Data), binary.BigEndian, &extData); err != nil {
		return nil, fmt.Errorf("failed to parse crypto extension: %w", err)
	}
	if _, err := reader.(*os.File).Seek(int64(extData.Offset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to LUKS header at 0x%x: %w", extData.Offset, err)
	}

	var luks luksHeader
	if err := binary.Read(reader, binary.BigEndian, &luks); err != nil {
		return nil, fmt.Errorf("failed to read LUKS header: %w", err)
	}
	if string(luks.Magic[:]) != luksMagic {
		return nil, fmt.Errorf("invalid LUKS magic: %x", luks.Magic)
	}
	if luks.Version != 1 {
		return nil, fmt.Errorf("unsupported LUKS version: %d", luks.Version)
	}

	cipherName := string(bytes.Trim(luks.CipherName[:], "\x00"))
	cipherMode := string(bytes.Trim(luks.CipherMode[:], "\x00"))
	hashSpec := string(bytes.Trim(luks.HashSpec[:], "\x00"))

	// Validate cipher name
	normalizedCipher, err := luksCipherNameLookup(cipherName)
	if err != nil {
		return nil, fmt.Errorf("cipher name validation failed: %w", err)
	}

	// Parse cipher mode
	mode, ivgen, ivhash, err := parseCipherMode(cipherMode)
	if err != nil {
		return nil, fmt.Errorf("cipher mode parsing failed: %w", err)
	}

	// Validate hash spec
	hashFunc, _, err := luksHashNameLookup(hashAlgorithm(hashSpec))
	if err != nil {
		return nil, fmt.Errorf("hash spec validation failed: %w", err)
	}

	var masterKey []byte
	var essivCipher cipher.Block
	for _, slot := range luks.KeySlots {
		if slot.Active != luksKeyEnabled {
			continue
		}

		keyMaterialSize := int(luks.KeyBytes) * int(slot.Stripes)
		if keyMaterialSize%16 != 0 {
			continue
		}
		keyMaterialOffset := int64(extData.Offset) + int64(slot.KeyMaterialOffset)*sectorSize
		if _, err := reader.(*os.File).Seek(keyMaterialOffset, io.SeekStart); err != nil {
			continue
		}
		keyMaterial := make([]byte, keyMaterialSize)
		if _, err := io.ReadFull(reader, keyMaterial); err != nil {
			continue
		}

		derivedKey := pbkdf2.Key([]byte(password), slot.PasswordSalt[:], int(slot.PasswordIterations), int(luks.KeyBytes), hashFunc)

		if ivgen == ivGenESSIV {
			var err error
			essivCipher, err = initESSIV(derivedKey, ivhash, normalizedCipher)
			if err != nil {
				continue
			}
		}

		// Initialize data cipher for XTS if needed
		var dataCipher *xts.Cipher
		if mode == cipherModeXTS {
			var err error
			dataCipher, err = initXTS(derivedKey, normalizedCipher)
			if err != nil {
				continue
			}
		}

		// Decrypt key material using the same cipher mode and IV generator as payload
		config := &luksConfig{
			masterKey:   derivedKey,
			cipherName:  cipherName,
			cipherMode:  mode,
			ivGen:       ivgen,
			ivHash:      ivhash,
			hashSpec:    hashAlgorithm(hashSpec),
			keyBytes:    luks.KeyBytes,
			sectorSize:  sectorSize,
			dataCipher:  dataCipher,
			essivCipher: essivCipher,
		}
		splitKey, err := config.decryptData(keyMaterial, uint64(slot.KeyMaterialOffset))
		if err != nil {
			continue
		}

		// Reconstruct master key
		masterKeyCandidate, err := afMerge(splitKey, int(luks.KeyBytes), int(slot.Stripes), hashAlgorithm(hashSpec))
		if err != nil {
			continue
		}

		// Verify master key
		mkDigestCandidate := pbkdf2.Key(masterKeyCandidate, luks.MKDigestSalt[:], int(luks.MKDigestIterations), luksDigestSize, hashFunc)
		if bytes.Equal(mkDigestCandidate, luks.MKDigest[:]) {
			masterKey = masterKeyCandidate
			break
		}
	}
	if masterKey == nil {
		return nil, errors.New("no valid key slot found")
	}

	// Verify master key length
	masterKeyLen := int(luks.KeyBytes)
	if len(masterKey) != masterKeyLen {
		return nil, fmt.Errorf("invalid master key length %d for %s/%s (expected %d)", len(masterKey), cipherName, mode, masterKeyLen)
	}

	// Initialize data cipher
	var dataCipher *xts.Cipher
	if mode == cipherModeXTS {
		var err error
		dataCipher, err = initXTS(masterKey, normalizedCipher)
		if err != nil {
			return nil, fmt.Errorf("failed to create XTS cipher: %w", err)
		}
	}

	// Initialize ESSIV cipher for payload decryption
	if ivgen == ivGenESSIV {
		var err error
		essivCipher, err = initESSIV(masterKey, ivhash, normalizedCipher)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize ESSIV cipher for payload: %w", err)
		}
	}

	return &luksConfig{
		masterKey:      masterKey,
		cipherName:     cipherName,
		cipherMode:     mode,
		ivGen:          ivgen,
		ivHash:         ivhash,
		hashSpec:       hashAlgorithm(hashSpec),
		keyBytes:       luks.KeyBytes,
		sectorSize:     sectorSize,
		encryptedStart: alignUp(extData.Offset+extData.Length, 1<<header.ClusterBits),
		dataCipher:     dataCipher,
		essivCipher:    essivCipher,
	}, nil
}

// parseCipherMode parses <cipher-mode>-<iv-generator>[:<iv-hash>] format
func parseCipherMode(cMode string) (cipherMode, ivGen, hashAlgorithm, error) {
	parts := strings.Split(strings.ToLower(cMode), "-")
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("invalid cipher mode format: %s", cMode)
	}
	var mode cipherMode
	switch parts[0] {
	case "xts":
		mode = cipherModeXTS
	case "cbc":
		mode = cipherModeCBC
	default:
		return "", "", "", fmt.Errorf("unsupported cipher mode: %s", parts[0])
	}
	var ivgen ivGen
	var ivhash hashAlgorithm
	if strings.Contains(parts[1], ":") {
		// Handle <iv-generator>:<iv-hash>
		subparts := strings.Split(parts[1], ":")
		if len(subparts) != 2 {
			return "", "", "", fmt.Errorf("invalid iv-generator format: %s", parts[1])
		}
		ivgen = ivGen(subparts[0])
		ivhash = hashAlgorithm(subparts[1])
	} else {
		ivgen = ivGen(parts[1])
	}
	switch ivgen {
	case ivGenPlain, ivGenPlain64, ivGenESSIV:
		// Valid IV generators
	default:
		return "", "", "", fmt.Errorf("unsupported IV generator: %s", ivgen)
	}
	if ivgen == ivGenESSIV {
		if ivhash == "" {
			return "", "", "", errors.New("missing iv-hash for essiv mode")
		}
		if ivhash != hashSHA1 && ivhash != hashSHA256 {
			return "", "", "", fmt.Errorf("unsupported iv-hash: %s", ivhash)
		}
	} else {
		ivhash = "" // Ignore iv-hash for non-essiv, per dm-crypt compatibility
	}
	return mode, ivgen, ivhash, nil
}
