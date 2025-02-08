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

package etcshadow

import (
	"context"
	"errors"
	"strings"

	"github.com/GehirnInc/crypt/sha512_crypt"
	"golang.org/x/crypto/bcrypt"
)

// ErrNotCracked returned when a cracker did not find a matching password.
var ErrNotCracked = errors.New("not cracked")

// Cracker interface is implemented by types which know how to crack hashes.
type Cracker interface {
	// Crack returns (password,nil) on success and ("", ErrNotCracked) on failure.
	Crack(ctx context.Context, hash string) (string, error)
}

type passwordCracker struct {
	bcryptCracker      Cracker
	sha512cryptCracker Cracker
}

// NewPasswordCracker returns a cracker that can attempt to find the password for a given hash.
func NewPasswordCracker() Cracker {
	return passwordCracker{
		bcryptCracker:      bcryptCracker{},
		sha512cryptCracker: sha512CryptCracker{},
	}
}

func (c passwordCracker) Crack(ctx context.Context, hash string) (string, error) {
	// TODO(b/383302694): Add more hash algos.
	switch {
	case strings.HasPrefix(hash, "$2"):
		return c.bcryptCracker.Crack(ctx, hash)
	case strings.HasPrefix(hash, sha512_crypt.MagicPrefix):
		return c.sha512cryptCracker.Crack(ctx, hash)
	}
	return "", ErrNotCracked
}

// Cracker for bcrypt password hashes.
type bcryptCracker struct {
}

func (c bcryptCracker) Crack(ctx context.Context, hash string) (string, error) {
	for _, v := range topPasswords {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(v))
		if err == nil {
			return v, nil
		}
	}
	return "", ErrNotCracked
}

// Cracker for sha512crypt password hashes.
type sha512CryptCracker struct {
}

func (c sha512CryptCracker) Crack(ctx context.Context, hash string) (string, error) {
	crypter := sha512_crypt.New()
	for _, v := range topPasswords {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		err := crypter.Verify(hash, []byte(v))
		if err == nil {
			return v, nil
		}
	}
	return "", ErrNotCracked
}
