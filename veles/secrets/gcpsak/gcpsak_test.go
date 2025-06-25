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

package gcpsak_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

const (
	exampleKeyID          = "123456789abcdef0123456789abcdef012345678"
	exampleServiceAccount = "some-service-account@some-project-id.iam.gserviceaccount.com"
	// examplePrivateKey was generated manually specifically for this test and
	// does not actually belong to any real GCP service account.
	// The corresponding signature is hardcoded below.
	examplePrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi
0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN
tWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn
jWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC
zLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN
dNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W
J9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i
Ofoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv
1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV
3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h
kkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN
A6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o
R34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy
oEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu
Z8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx
Hajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB
m7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww
nr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU
F6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2
FQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h
Y9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3
odxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt
H0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct
H7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi
2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack
RsacStLCR1jUc6EzaCaj61w=
-----END PRIVATE KEY-----
`
	// The certificates provided by the Google Cloud Metadata server of course
	// contain a lot more information but for the intents and purposes of this
	// test, we can synthesize a fake. It contains the public key corresponding
	// to examplePrivateKey.
	exampleCertificate = `-----BEGIN CERTIFICATE-----
MIICkDCCAXigAwIBAgIUF71g4w7a5jGaR/NV9RboV+P+blQwDQYJKoZIhvcNAQEL
BQAwADAiGA8wMDAxMDEwMTAwMDAwMFoYDzAwMDEwMTAxMDAwMDAwWjAAMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArEH0OduI0grQItEW81rqN0uoyY08
nWHkjv3CqLhDpoSi6FMVlRFxgu9DBS/3neV6qUfNmpiWcM8SzbVkAAcCxi5Hw+Gg
+DAFqa0o0QL/WElCObPjY4qoKczbpcrIEJig8t84KuHAELSs541oGYzK11UM9VIU
WQIjv8Q2/8erMP+AzCabcNsx78cTJ0Uf6Pd1DPn8iei/fVDYQsyyKfSE/CUBIULu
vD24K4btOLMq1DmD61i7aQg3PNIT1vQP1CYlmJGXMYR0hF7bDXTRpQeUvoyBGQ6s
i2h0Sdr2rneQhHfAk0T4SDNQEp49+vhckANmEWhbyaH8O+jdVifQTKyWnQIDAQAB
MA0GCSqGSIb3DQEBCwUAA4IBAQBaEQlqxmTsyequ9xxJrILB/AWTkyNIYf4iS98H
XSBMx1rkdWpm1dRoXHpwPA5uWvSIrlWPXEZgbYy+qUTRetwOqpCm7oLSl+VUiHol
sR1wAPsG2Oe23GzTXuu6OCeoJpjYCw1NETRJ4aEDpvHGYARHCPUGPGUY09eMNDk1
mMV2122qCuk5SXth/gxeJdDA4WaAhWUUwu2CwuTAqIe0aTs/kY5yo1nQlcO2yEnZ
F/WGWO49hwu0rllD9/cU4KUKIN0dGyJUU9vIzyp4fyN2IKGxmKnnfMv9Ixhnyodc
EECZ53cSGqXaVUy01joqpyAh+rCICumd3uAM0a2vxOYR3hV+
-----END CERTIFICATE-----`
)

var (
	// exampleSignature is the signature for examplePrivateKey obtained by using
	// gcpsak.sign() on it. Hardcoding it here is fine because the signature logic
	// should never change.
	exampleSignature = []byte{
		78, 94, 170, 137, 175, 34, 187, 129, 234, 202, 96, 116, 144, 240, 39, 186,
		168, 48, 27, 153, 225, 133, 242, 243, 209, 144, 25, 137, 159, 131, 57, 88,
		135, 43, 118, 222, 162, 196, 149, 124, 31, 51, 71, 112, 217, 85, 185, 68,
		254, 179, 241, 252, 108, 251, 153, 165, 158, 71, 194, 190, 17, 246, 12, 66,
		16, 221, 39, 52, 111, 136, 173, 31, 20, 113, 4, 8, 26, 119, 135, 133, 202,
		179, 205, 168, 74, 129, 238, 128, 209, 177, 119, 54, 128, 47, 34, 170, 17,
		195, 97, 177, 58, 130, 75, 242, 186, 85, 54, 7, 207, 207, 81, 135, 139, 54,
		79, 93, 2, 34, 194, 91, 101, 15, 87, 54, 162, 142, 184, 23, 182, 104, 32,
		50, 20, 189, 209, 171, 188, 220, 54, 125, 108, 22, 212, 103, 7, 219, 134,
		239, 38, 217, 140, 251, 154, 226, 85, 81, 206, 220, 136, 109, 18, 147, 217,
		22, 57, 30, 217, 234, 174, 245, 67, 144, 80, 36, 167, 44, 116, 94, 230, 86,
		42, 186, 94, 43, 166, 161, 17, 192, 163, 43, 56, 174, 154, 61, 248, 142, 22,
		79, 43, 140, 13, 229, 244, 137, 228, 63, 71, 119, 142, 147, 110, 172, 253,
		76, 150, 237, 152, 151, 255, 196, 172, 86, 109, 21, 141, 160, 29, 233, 32,
		19, 127, 7, 80, 85, 102, 142, 165, 106, 103, 28, 31, 57, 209, 234, 43, 119,
		247, 9, 125, 79, 25, 48, 66, 196, 23, 139,
	}
)

func genKeyAndCert(t *testing.T) (string, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})
	if privPEM == nil {
		t.Fatal("pem.EncodeToMemory() failed for private key")
	}
	cert := x509.Certificate{}
	certDER, err := x509.CreateCertificate(rand.Reader, &cert, &cert, priv.Public(), priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if certPEM == nil {
		t.Fatalf("pem.EncodeToMemory() failed for certificate")
	}
	return string(privPEM), string(certPEM)
}
