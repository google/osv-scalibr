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

package etcshadow_test

import (
	"context"
	"testing"

	"github.com/google/osv-scalibr/detector/weakcredentials/etcshadow"
)

// All the hashes below are for the string "Password123" and where obtained
// running: 'mkpasswd -m METHOD PASSWORD'.
//
// Note the obsolete descrypt will limit password to 8 characters and
// there will be cracked as the value 'Password'.
var testHashes = map[string]string{
	"yescrypt":      "$y$j9T$huXYrFRxr5.EtlA/GqJQg1$R36Nu5MbY5YM0SzRaWbBPyGpM7KMcWtbUmBq5gDZA9B",
	"gost-yescrypt": "$gy$j9T$i.krMgTvuXE2doi6Hguka/$qwn482j7gJbWZNQ3cF0YdKAud.C3vUIorQGsF0ryox3",
	"scrypt":        "$7$CU..../....oupVTCfqrgm0HQkQR3JaB1$2m9CeDTqL8i5pMsc8E73A2bCIsvQPhntxBmSVlbrql2",
	"bcrypt":        "$2b$05$IYDlXvHmeORyyiUwu8KKuek2LE8VrxIYZ2skPvRDDNngpXJHRq7sG",
	"bcrypt-a":      "$2a$05$pRmHHyGfKl9/9AZLORG/neKW39VHGF4ptLT2MLq1BqQOnbwL6DQM6",
	"sha512crypt":   "$6$5dZ5RtTlA.rNzi8o$sE23IbqB0Q57/7nI2.AqazHUnWGP06HmkadfBJ90mHgAHkWVZteoaUWV25jITMIUXC/buIgZ9hU2JYQM5qGZn1",
	"sha256crypt":   "$5$bMDt75aAcRJMgynJ$7dvcQe0UPWAlpr4VFNQI2iDDUQLgwcaTOV5oQVSIR56",
	"sunmd5":        "$md5,rounds=46947$ieGPlcPv$$sJ4xQqZ5DHZu0Bma2EW/..",
	"md5crypt":      "$1$emQTNiRX$kZ2UzRTLgfsTBGS0M1OOb1",
	"NT-Hash":       "$3$$58a478135a93ac3bf058a5ea0e8fdb71",
	// Quite old and insecure password hash algorithms. Do not use the $ format.
	"bsdicrypt": "_J9..Sc51o5Op8yDIuHc",
	"descrypt":  "chERDiI95PGCQ",
}

func TestPasswordHashCracker(t *testing.T) {
	cracker := etcshadow.NewPasswordCracker()
	crackableHash := map[string]bool{
		"bcrypt":      true,
		"bcrypt-a":    true,
		"sha512crypt": true,
	}
	for k, v := range testHashes {
		password, err := cracker.Crack(t.Context(), v)
		_, isCrackable := crackableHash[k]
		if isCrackable && err != nil {
			t.Errorf("not cracked supported hash: [%v] [%v]", k, v)
		} else if !isCrackable && err == nil {
			t.Errorf("cracked unsupported hash: [%v] [%v] [%v]", k, password, v)
		} else if password != "Password123" && err == nil {
			t.Errorf("cracked password is not 'Password123': [%v] [%v] [%v]", k, password, v)
		}
	}
}

func TestPasswordHashCrackerBadHashes(t *testing.T) {
	cracker := etcshadow.NewPasswordCracker()
	badValues := []string{
		"$2$",
		"$2$123",
		"$2$123$",
		"$6$",
		"$6$123",
		"$6$123$",
		"*",
		"!!",
		"!",
		"$2$*",
		"$2$!",
		"$6$*",
		"$6$!",
	}

	for _, v := range badValues {
		if _, err := cracker.Crack(t.Context(), v); err != etcshadow.ErrNotCracked {
			t.Errorf("expected ErrNotCracked on hash [%s] received [%v]", v, err)
		}
	}
}

func TestPasswordHashCrackerCancelled(t *testing.T) {
	cracker := etcshadow.NewPasswordCracker()
	ctx, cancelFunc := context.WithCancel(t.Context())
	cancelFunc()
	_, err := cracker.Crack(ctx, testHashes["bcrypt"])
	if err != ctx.Err() {
		t.Errorf("expected error %v on cancelled context, received error %v", ctx.Err(), err)
	}
}
