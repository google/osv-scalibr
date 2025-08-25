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

package privatekey_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/google/osv-scalibr/veles/secrets/privatekey"
)

func TestDetector_PEMVariants(t *testing.T) {
	d := privatekey.NewDetector()

	cases := []struct {
		name, data string
	}{
		{"Generic", `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDDwxXFmUGrIkQZ
AJ1yFkkXrOOCH3RL4QsGk24xTj7iO/ozauKXoVys3wKAzK9iwlfBY36kqqn0hvL9
YhrnHAGfQJTGMnwkbZvWV6u6IKWxKqPGQp4ULIbveYd6FoXPMcwULdoRQeR+kez8
aPzyu/L4cnlk31J6WqpNnjohmndAkaRnx/mGRYcn+xDvOcJbmLSHQHYgCigHzENg
uilu4N9KLsD6+N0c1prr79STsiR9HRozkS+ySpiS1tG9jYMAlKSp3L+hgQDqvcK5
j5zyJx7iDmIdmQjmbpnLaxj8cjW+c5FzEoqZ2pXCuLDMTOfGnzFxrRzf5Mc8tw+9
hPRrkv+fAgMBAAECggEAGn6+5Z2We7kJinDA3n4Rqnil2iizrslomp09nsK+VBRW
Crt+q5MVXfhY+GG7oxw2kGAM9fB7TDMvlAfBKGJr/cfZ2vFeR/flzZ7UCT797fqd
a+n8RzK3mJXUNjvyJFbTDjAegZNvf4n0jz0ObzPs8J9dur9XBGRdBGBT8dRcK4rN
+F9qh8JYwM+cXYbDjKvoLoxTSeCxREJ2KHVueCGxTBAwkmUXiF0jnxueqLoThoAT
TLzyTYw+20F4vRJMVpLZO6X7GOht1NkIbi4vFTKh8iAnUGXRUZ8W+evW2NykGd0q
0QsDsFO/Oc8Xn2DZTCutGUsHeDxq4XApnNk04t13sQKBgQDw+79+6E9xXjYUwZrG
TyMb1j1va/oGEVaxPgSGm5RHcjW4xesdCftOT3eckFNVWzk4V7sG9as/s0FMQ0M3
TchY8FkeK/iOBbZDExmmeDPvxzexC7nRCB+NOJZML9zCN8PTkje96uXWjTCCbJTu
zqnliDLTBsXJQt1XJXU5ZnIQxQKBgQDP9fNEyRzNXttKL7lj9zutDe5AMHS10hoR
gMBnRKlte3VKZfRauna/Lv3afhFHwZAEWnkUhQUK9lE8U9EnIoPNPW7jAaO69BHo
1/gXR9rZibiTnYczCS9XlXaER3139Mjjn3W0v12Vi9Fylqgx2oyb1HaDtRr6HNun
P33B8dbNEwKBgQDoOnLMJauJILUVQ42X1eOLi+YgXfnPpx3YKF/MKFm4kENdEL4G
efwH92TZJ+xmsUZvGXxOtKiW9nPSvm8j+H092EDJZq5cjvyZnup1FhlW1LDCmP40
hpOBUCrmuKkRMRQx6xJ0ns1m+SDqTyEnEVmArMPtwPURgrIyrRJOgn8h0QKBgAK4
K6M1ogvJdsKklx8Ih54+tWPfflc2VSLvdRSkoDaPS7xaUvSwxYbAfY9S4LT4ggKc
kELFbohzKiLI0c5aNDEF4aJUTijOskFCObtMND9t/pznjXIMZ7MUgEVAjhJ4f/wC
BM8FRZsEBgwijjaAriAHijk0sBKfN/wa53EW0YFDAoGAE+k5Eq/L+/G4pDcOwm55
kEzYclnfD38ZM9DfPB6k0K55TubLL9PeltRkR5yy4tjlBlDPx6wzMhbd0Xq3iCzq
Twanj5YBWrq2yV2fqWgvyz3LIqlhmDNW89ThWmk7XYtD0em9dnEXlpH0JTxdQpCF
tGOp/d/V3F66yalNSTXNbkA=
-----END PRIVATE KEY-----
`},
		{"EC", `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJzFi+JZBWu0ivAZgkOuKD8OMs69xpRj7SqmVlqSbqb7oAoGCCqGSM49
AwEHoUQDQgAE8cg/mxOyT54gVISe5vMWP//1lUcElOs5T2SNJ+PbCrzt6SrwRiM3
Um1TNu0yGY4QbHWoW9iq8ZSVN7SSrcAong==
-----END EC PRIVATE KEY-----
`},
		{"OpenSSH", `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEA2QxOpGlLR/cvp54L6jwu+edKTVdPFs9K3w17oI1w5DhWTEce6nh7
nCv+e3luyWbxuxnpyEiJiqTP7FjdX/lzKMHTvhe1PTP5nIIQhKQCunE4x9k5NrK1BZBKGo
Ypg343xdPtGLNRdcaAIppuWhbmWCpgciYkAgcae7qP8ZujVCcAAAIIQp//80Kf//MAAAAH
c3NoLXJzYQAAAIEA2QxOpGlLR/cvp54L6jwu+edKTVdPFs9K3w17oI1w5DhWTEce6nh7nC
v+e3luyWbxuxnpyEiJiqTP7FjdX/lzKMHTvhe1PTP5nIIQhKQCunE4x9k5NrK1BZBKGoYp
g343xdPtGLNRdcaAIppuWhbmWCpgciYkAgcae7qP8ZujVCcAAAADAQABAAAAgQDKSYYiBW
B8OgzYE5zXOjAuCTpeyriTca8+I7rM8AX/LeKAROizbocGDpqnSY3Pd3pj/sq8N5648NI4
XLo18K853cdGKdpbZHxJ//1CSp4s2YEbzJH2AYVITDv2Lc/f3Ze2Ra93y4RQDmz310R3+T
9vQNi0F22XEb7kXa75ombdAQAAAEAmqs7ILluwoEzCIwJvl8qBAqAfGnDbTC1uFsUwlskX
Ay6Ku8/HplhGvnl0fL51B7BC38qXopDRYU0avvACpnOcAAAAQQDtC80p4AE+fVW7Ltngca
8K1TrL/GWkZSnuruXPiXiZFyQYoqiXyllLekjpBDxQSiKbGWa7t7AScAyso6EBbZvRAAAA
QQDqZyhZXF7vc5Com3IzHkY2apHsWq5N8A5BQd9Wzh9KsOTvrH1W27m5TNcX7joVpHSYMl
YE2rTfFMPD137muQZ3AAAAEnlzYXhlbmF4QGdtYWlsLmNvbQ==
-----END OPENSSH PRIVATE KEY-----
`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			secrets, offsets := d.Detect([]byte(tc.data))
			if len(secrets) != 1 {
				t.Fatalf("expected 1 match, got %d (offsets: %v)", len(secrets), offsets)
			}
		})
	}
}

func TestDetector_DERVariants(t *testing.T) {
	d := privatekey.NewDetector()
	t.Run("PKCS1", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		der := x509.MarshalPKCS1PrivateKey(key)

		secrets, offsets := d.Detect(der)
		if len(secrets) != 1 {
			t.Fatalf("expected 1 matches, got %d (offsets: %v)", len(secrets), offsets)
		}
	})

	t.Run("PKCS8", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		der, _ := x509.MarshalPKCS8PrivateKey(key)

		secrets, offsets := d.Detect(der)
		if len(secrets) != 1 {
			t.Fatalf("expected 1 matches, got %d (offsets: %v)", len(secrets), offsets)
		}
	})

	t.Run("EC", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalECPrivateKey(key)

		secrets, offsets := d.Detect(der)
		if len(secrets) != 1 {
			t.Fatalf("expected 1 matches, got %d (offsets: %v)", len(secrets), offsets)
		}
	})
}

func TestDetector_MultipleBlocksIndependent(t *testing.T) {
	d := privatekey.NewDetector()
	data := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJzFi+JZBWu0ivAZgkOuKD8OMs69xpRj7SqmVlqSbqb7oAoGCCqGSM49
AwEHoUQDQgAE8cg/mxOyT54gVISe5vMWP//1lUcElOs5T2SNJ+PbCrzt6SrwRiM3
Um1TNu0yGY4QbHWoW9iq8ZSVN7SSrcAong==
-----END EC PRIVATE KEY-----
` +
		"SOMEDATA\n" +
		`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJzFi+JZBWu0ivAZgkOuKD8OMs69xpRj7SqmVlqSbqb7oAoGCCqGSM49
AwEHoUQDQgAE8cg/mxOyT54gVISe5vMWP//1lUcElOs5T2SNJ+PbCrzt6SrwRiM3
Um1TNu0yGY4QbHWoW9iq8ZSVN7SSrcAong==
-----END EC PRIVATE KEY-----
`
	secrets, offsets := d.Detect([]byte(data))

	if len(secrets) != 2 {
		t.Fatalf("expected 2 matches, got %d (offsets: %v)", len(secrets), offsets)
	}
}

func TestDetector_InvalidInputs(t *testing.T) {
	d := privatekey.NewDetector()

	cases := []struct {
		name string
		data []byte
	}{
		{
			name: "CorruptedPEM",
			data: []byte("-----BEGIN PRIVATE KEY-----\nINVALIDDATA\n-----END PRIVATE KEY-----"),
		},
		{
			name: "MissingDashes",
			data: []byte("BEGIN PRIVATE KEY (missing dashes) END PRIVATE KEY"),
		},
		{
			name: "RandomString",
			data: []byte("just some random text that looks nothing like a key"),
		},
		{
			name: "InvalidDER",
			data: []byte("notaderkey"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			secrets, offsets := d.Detect(tc.data)
			if len(secrets) != 0 {
				t.Fatalf("expected 0 matches, got %d (offsets: %v)", len(secrets), offsets)
			}
		})
	}
}
