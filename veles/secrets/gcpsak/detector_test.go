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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gcpsak"
)

// TestDetector_truePositives tests the detector's ability to find GCP SAK
// in specific scenarios where the original key material has been altered e.g.
// through escaping. All scenarios work with a single known key.
//
// One challenge here is that the private key itself contains newlines which can
// be subject to escaping. So our test cases need to account for that properly.
func TestDetector_truePositives(t *testing.T) {
	scenarios := []struct {
		name     string
		detector *gcpsak.Detector
		want     []veles.Secret
	}{
		{
			name:     "default detector",
			detector: gcpsak.NewDetector(),
			want: []veles.Secret{
				gcpsak.GCPSAK{
					PrivateKeyID:   exampleKeyID,
					ServiceAccount: exampleServiceAccount,
					Signature:      exampleSignature,
				},
			},
		},
		{
			name:     "with extra fields",
			detector: gcpsak.NewDetectorWithExtraFields(false),
			want: []veles.Secret{
				gcpsak.GCPSAK{
					PrivateKeyID:   exampleKeyID,
					ServiceAccount: exampleServiceAccount,
					Signature:      exampleSignature,
					Extra: &gcpsak.ExtraFields{
						Type:                    "service_account",
						ProjectID:               "some-project-id",
						ClientID:                "some-client-id",
						AuthURI:                 "https://accounts.google.com/o/oauth2/auth",
						TokenURI:                "https://oauth2.googleapis.com/token",
						AuthProviderX509CertURL: "https://www.googleapis.com/oauth2/v1/certs",
						ClientX509CertURL:       "https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com",
						UniverseDomain:          "",
					},
				},
			},
		},
		{
			name:     "with private key fields",
			detector: gcpsak.NewDetectorWithExtraFields(true),
			want: []veles.Secret{
				gcpsak.GCPSAK{
					PrivateKeyID:   exampleKeyID,
					ServiceAccount: exampleServiceAccount,
					Signature:      exampleSignature,
					Extra: &gcpsak.ExtraFields{
						Type:                    "service_account",
						ProjectID:               "some-project-id",
						ClientID:                "some-client-id",
						AuthURI:                 "https://accounts.google.com/o/oauth2/auth",
						TokenURI:                "https://oauth2.googleapis.com/token",
						AuthProviderX509CertURL: "https://www.googleapis.com/oauth2/v1/certs",
						ClientX509CertURL:       "https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com",
						UniverseDomain:          "",
						PrivateKey:              examplePrivateKey,
					},
				},
			},
		},
	}
	cases := []struct {
		name  string
		input string
	}{
		{
			name: "JSON_(pretty)",
			input: `{
			"type": "service_account",
			"project_id": "some-project-id",
			"private_key_id": "123456789abcdef0123456789abcdef012345678",
			"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\nRsacStLCR1jUc6EzaCaj61w=\n-----END PRIVATE KEY-----\n",
			"client_email": "some-service-account@some-project-id.iam.gserviceaccount.com",
			"client_id": "some-client-id",
			"auth_uri": "https://accounts.google.com/o/oauth2/auth",
			"token_uri": "https://oauth2.googleapis.com/token",
			"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
			"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com"
		}`,
		},
		{
			name:  "JSON (flat)",
			input: `{"type":"service_account","project_id":"some-project-id","private_key_id":"123456789abcdef0123456789abcdef012345678","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\nRsacStLCR1jUc6EzaCaj61w=\n-----END PRIVATE KEY-----\n","client_email":"some-service-account@some-project-id.iam.gserviceaccount.com","client_id":"some-client-id","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_x509_cert_url":"https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com"}`,
		},
		{
			name: "Sorted_JSON_(pretty)",
			input: `{
			"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
			"auth_uri": "https://accounts.google.com/o/oauth2/auth",
			"client_email": "some-service-account@some-project-id.iam.gserviceaccount.com",
			"client_id": "some-client-id",
			"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com",
			"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\nRsacStLCR1jUc6EzaCaj61w=\n-----END PRIVATE KEY-----\n",
			"private_key_id": "123456789abcdef0123456789abcdef012345678",
			"project_id": "some-project-id",
			"token_uri": "https://oauth2.googleapis.com/token",
			"type": "service_account"
		}`,
		},
		{
			name:  "Escaped JSON (pretty)",
			input: `"{\n  \"type\": \"service_account\",\n  \"project_id\": \"some-project-id\",\n  \"private_key_id\": \"123456789abcdef0123456789abcdef012345678\",\n  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\\nRsacStLCR1jUc6EzaCaj61w=\\n-----END PRIVATE KEY-----\\n\",\n  \"client_email\": \"some-service-account@some-project-id.iam.gserviceaccount.com\",\n  \"client_id\": \"some-client-id\",\n  \"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\",\n  \"token_uri\": \"https://oauth2.googleapis.com/token\",\n  \"auth_provider_x509_cert_url\": \"https://www.googleapis.com/oauth2/v1/certs\",\n  \"client_x509_cert_url\": \"https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com\"\n}"`,
		},
		{
			name:  "Nested JSON (pretty)",
			input: `{"Key":"{\n  \"type\": \"service_account\",\n  \"project_id\": \"some-project-id\",\n  \"private_key_id\": \"123456789abcdef0123456789abcdef012345678\",\n  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\\nRsacStLCR1jUc6EzaCaj61w=\\n-----END PRIVATE KEY-----\\n\",\n  \"client_email\": \"some-service-account@some-project-id.iam.gserviceaccount.com\",\n  \"client_id\": \"some-client-id\",\n  \"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\",\n  \"token_uri\": \"https://oauth2.googleapis.com/token\",\n  \"auth_provider_x509_cert_url\": \"https://www.googleapis.com/oauth2/v1/certs\",\n  \"client_x509_cert_url\": \"https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com\"\n}"}`,
		},
		{
			name:  "Double escaped JSON (pretty)",
			input: `"\"{\\n  \\\"type\\\": \\\"service_account\\\",\\n  \\\"project_id\\\": \\\"some-project-id\\\",\\n  \\\"private_key_id\\\": \\\"123456789abcdef0123456789abcdef012345678\\\",\\n  \\\"private_key\\\": \\\"-----BEGIN PRIVATE KEY-----\\\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\\\\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\\\\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\\\\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\\\\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\\\\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\\\\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\\\\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\\\\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\\\\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\\\\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\\\\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\\\\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\\\\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\\\\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\\\\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\\\\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\\\\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\\\\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\\\\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\\\\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\\\\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\\\\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\\\\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\\\\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\\\\nRsacStLCR1jUc6EzaCaj61w=\\\\n-----END PRIVATE KEY-----\\\\n\\\",\\n  \\\"client_email\\\": \\\"some-service-account@some-project-id.iam.gserviceaccount.com\\\",\\n  \\\"client_id\\\": \\\"some-client-id\\\",\\n  \\\"auth_uri\\\": \\\"https://accounts.google.com/o/oauth2/auth\\\",\\n  \\\"token_uri\\\": \\\"https://oauth2.googleapis.com/token\\\",\\n  \\\"auth_provider_x509_cert_url\\\": \\\"https://www.googleapis.com/oauth2/v1/certs\\\",\\n  \\\"client_x509_cert_url\\\": \\\"https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com\\\"\\n}\""`,
		},
		{
			name:  "Nested and escaped JSON (pretty)",
			input: `"{\"Key\":\"{\\n  \\\"type\\\": \\\"service_account\\\",\\n  \\\"project_id\\\": \\\"some-project-id\\\",\\n  \\\"private_key_id\\\": \\\"123456789abcdef0123456789abcdef012345678\\\",\\n  \\\"private_key\\\": \\\"-----BEGIN PRIVATE KEY-----\\\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\\\\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\\\\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\\\\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\\\\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\\\\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\\\\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\\\\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\\\\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\\\\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\\\\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\\\\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\\\\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\\\\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\\\\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\\\\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\\\\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\\\\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\\\\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\\\\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\\\\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\\\\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\\\\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\\\\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\\\\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\\\\nRsacStLCR1jUc6EzaCaj61w=\\\\n-----END PRIVATE KEY-----\\\\n\\\",\\n  \\\"client_email\\\": \\\"some-service-account@some-project-id.iam.gserviceaccount.com\\\",\\n  \\\"client_id\\\": \\\"some-client-id\\\",\\n  \\\"auth_uri\\\": \\\"https://accounts.google.com/o/oauth2/auth\\\",\\n  \\\"token_uri\\\": \\\"https://oauth2.googleapis.com/token\\\",\\n  \\\"auth_provider_x509_cert_url\\\": \\\"https://www.googleapis.com/oauth2/v1/certs\\\",\\n  \\\"client_x509_cert_url\\\": \\\"https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com\\\"\\n}\"}"`,
		},
		{
			name:  "Escaped and nested JSON (pretty)",
			input: `{"Key":"\"{\\n  \\\"type\\\": \\\"service_account\\\",\\n  \\\"project_id\\\": \\\"some-project-id\\\",\\n  \\\"private_key_id\\\": \\\"123456789abcdef0123456789abcdef012345678\\\",\\n  \\\"private_key\\\": \\\"-----BEGIN PRIVATE KEY-----\\\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\\\\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\\\\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\\\\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\\\\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\\\\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\\\\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\\\\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\\\\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\\\\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\\\\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\\\\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\\\\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\\\\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\\\\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\\\\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\\\\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\\\\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\\\\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\\\\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\\\\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\\\\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\\\\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\\\\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\\\\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\\\\nRsacStLCR1jUc6EzaCaj61w=\\\\n-----END PRIVATE KEY-----\\\\n\\\",\\n  \\\"client_email\\\": \\\"some-service-account@some-project-id.iam.gserviceaccount.com\\\",\\n  \\\"client_id\\\": \\\"some-client-id\\\",\\n  \\\"auth_uri\\\": \\\"https://accounts.google.com/o/oauth2/auth\\\",\\n  \\\"token_uri\\\": \\\"https://oauth2.googleapis.com/token\\\",\\n  \\\"auth_provider_x509_cert_url\\\": \\\"https://www.googleapis.com/oauth2/v1/certs\\\",\\n  \\\"client_x509_cert_url\\\": \\\"https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com\\\"\\n}\""}`,
		},
		{
			name:  "Escaped JSON (flat)",
			input: `"{\"type\":\"service_account\",\"project_id\":\"some-project-id\",\"private_key_id\":\"123456789abcdef0123456789abcdef012345678\",\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\\nRsacStLCR1jUc6EzaCaj61w=\\n-----END PRIVATE KEY-----\\n\",\"client_email\":\"some-service-account@some-project-id.iam.gserviceaccount.com\",\"client_id\":\"some-client-id\",\"auth_uri\":\"https://accounts.google.com/o/oauth2/auth\",\"token_uri\":\"https://oauth2.googleapis.com/token\",\"auth_provider_x509_cert_url\":\"https://www.googleapis.com/oauth2/v1/certs\",\"client_x509_cert_url\":\"https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com\"}"`,
		},
		{
			name:  "Nested JSON (flat)",
			input: `{"Key":"{\"type\":\"service_account\",\"project_id\":\"some-project-id\",\"private_key_id\":\"123456789abcdef0123456789abcdef012345678\",\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\\nRsacStLCR1jUc6EzaCaj61w=\\n-----END PRIVATE KEY-----\\n\",\"client_email\":\"some-service-account@some-project-id.iam.gserviceaccount.com\",\"client_id\":\"some-client-id\",\"auth_uri\":\"https://accounts.google.com/o/oauth2/auth\",\"token_uri\":\"https://oauth2.googleapis.com/token\",\"auth_provider_x509_cert_url\":\"https://www.googleapis.com/oauth2/v1/certs\",\"client_x509_cert_url\":\"https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com\"}"}`,
		},
		{
			name:  "Four times escaped JSON (flat)",
			input: `"\"\\\"\\\\\\\"{\\\\\\\\\\\\\\\"type\\\\\\\\\\\\\\\":\\\\\\\\\\\\\\\"service_account\\\\\\\\\\\\\\\",\\\\\\\\\\\\\\\"project_id\\\\\\\\\\\\\\\":\\\\\\\\\\\\\\\"some-project-id\\\\\\\\\\\\\\\",\\\\\\\\\\\\\\\"private_key_id\\\\\\\\\\\\\\\":\\\\\\\\\\\\\\\"123456789abcdef0123456789abcdef012345678\\\\\\\\\\\\\\\",\\\\\\\\\\\\\\\"private_key\\\\\\\\\\\\\\\":\\\\\\\\\\\\\\\"-----BEGIN PRIVATE KEY-----\\\\\\\\\\\\\\\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\\\\\\\\\\\\\\\\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\\\\\\\\\\\\\\\\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\\\\\\\\\\\\\\\\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\\\\\\\\\\\\\\\\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\\\\\\\\\\\\\\\\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\\\\\\\\\\\\\\\\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\\\\\\\\\\\\\\\\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\\\\\\\\\\\\\\\\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\\\\\\\\\\\\\\\\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\\\\\\\\\\\\\\\\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\\\\\\\\\\\\\\\\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\\\\\\\\\\\\\\\\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\\\\\\\\\\\\\\\\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\\\\\\\\\\\\\\\\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\\\\\\\\\\\\\\\\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\\\\\\\\\\\\\\\\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\\\\\\\\\\\\\\\\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\\\\\\\\\\\\\\\\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\\\\\\\\\\\\\\\\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\\\\\\\\\\\\\\\\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\\\\\\\\\\\\\\\\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\\\\\\\\\\\\\\\\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\\\\\\\\\\\\\\\\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\\\\\\\\\\\\\\\\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\\\\\\\\\\\\\\\\nRsacStLCR1jUc6EzaCaj61w=\\\\\\\\\\\\\\\\n-----END PRIVATE KEY-----\\\\\\\\\\\\\\\\n\\\\\\\\\\\\\\\",\\\\\\\\\\\\\\\"client_email\\\\\\\\\\\\\\\":\\\\\\\\\\\\\\\"some-service-account@some-project-id.iam.gserviceaccount.com\\\\\\\\\\\\\\\",\\\\\\\\\\\\\\\"client_id\\\\\\\\\\\\\\\":\\\\\\\\\\\\\\\"some-client-id\\\\\\\\\\\\\\\",\\\\\\\\\\\\\\\"auth_uri\\\\\\\\\\\\\\\":\\\\\\\\\\\\\\\"https://accounts.google.com/o/oauth2/auth\\\\\\\\\\\\\\\",\\\\\\\\\\\\\\\"token_uri\\\\\\\\\\\\\\\":\\\\\\\\\\\\\\\"https://oauth2.googleapis.com/token\\\\\\\\\\\\\\\",\\\\\\\\\\\\\\\"auth_provider_x509_cert_url\\\\\\\\\\\\\\\":\\\\\\\\\\\\\\\"https://www.googleapis.com/oauth2/v1/certs\\\\\\\\\\\\\\\",\\\\\\\\\\\\\\\"client_x509_cert_url\\\\\\\\\\\\\\\":\\\\\\\\\\\\\\\"https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com\\\\\\\\\\\\\\\"}\\\\\\\"\\\"\""`,
		},
		{
			name: "C++_multiline_string",
			input: `constexpr char kKey[] = R"""({
			"type": "service_account",
			"project_id": "some-project-id",
			"private_key_id": "123456789abcdef0123456789abcdef012345678",
			"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\nRsacStLCR1jUc6EzaCaj61w=\n-----END PRIVATE KEY-----\n",
			"client_email": "some-service-account@some-project-id.iam.gserviceaccount.com",
			"client_id": "some-client-id",
			"auth_uri": "https://accounts.google.com/o/oauth2/auth",
			"token_uri": "https://oauth2.googleapis.com/token",
			"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
			"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com"
		})""";`,
		},
		{
			name: "Go_raw_string",
			input: "`" + `{
			"type": "service_account",
			"project_id": "some-project-id",
			"private_key_id": "123456789abcdef0123456789abcdef012345678",
			"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\nRsacStLCR1jUc6EzaCaj61w=\n-----END PRIVATE KEY-----\n",
			"client_email": "some-service-account@some-project-id.iam.gserviceaccount.com",
			"client_id": "some-client-id",
			"auth_uri": "https://accounts.google.com/o/oauth2/auth",
			"token_uri": "https://oauth2.googleapis.com/token",
			"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
			"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com"
	}` + "`",
		},
		{
			name: "Go_map_of_raw_strings",
			input: `
var foo = map[string]string{
"foo": ` + "`" + `{
		"type": "service_account",
				"project_id": "some-project-id",
				"private_key_id": "123456789abcdef0123456789abcdef012345678",
				"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\nRsacStLCR1jUc6EzaCaj61w=\n-----END PRIVATE KEY-----\n",
				"client_email": "some-service-account@some-project-id.iam.gserviceaccount.com",
				"client_id": "some-client-id",
				"auth_uri": "https://accounts.google.com/o/oauth2/auth",
				"token_uri": "https://oauth2.googleapis.com/token",
				"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
				"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com"
	}` + "`" + `,
}
`,
		},
		{
			name: "YAML_(multiline)",
			input: `  content: |
				{
					"type": "service_account",
					"project_id": "some-project-id",
					"private_key_id": "123456789abcdef0123456789abcdef012345678",
					"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\nRsacStLCR1jUc6EzaCaj61w=\n-----END PRIVATE KEY-----\n",
					"client_email": "some-service-account@some-project-id.iam.gserviceaccount.com",
					"client_id": "some-client-id",
					"auth_uri": "https://accounts.google.com/o/oauth2/auth",
					"token_uri": "https://oauth2.googleapis.com/token",
					"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
					"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com"
				}`,
		},
		{
			name: "Commented_out_JSON_(dashes)",
			input: `-- {
		--   "type": "service_account",
		--   "project_id": "some-project-id",
		--   "private_key_id": "123456789abcdef0123456789abcdef012345678",
		--   "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\nRsacStLCR1jUc6EzaCaj61w=\n-----END PRIVATE KEY-----\n",
		--   "client_email": "some-service-account@some-project-id.iam.gserviceaccount.com",
		--   "client_id": "some-client-id",
		--   "auth_uri": "https://accounts.google.com/o/oauth2/auth",
		--   "token_uri": "https://oauth2.googleapis.com/token",
		--   "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		--   "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com"
		-- }`,
		},
		{
			name: "Commented_out_JSON_(hashes)",
			input: `# {
		#   "type": "service_account",
		#   "project_id": "some-project-id",
		#   "private_key_id": "123456789abcdef0123456789abcdef012345678",
		#   "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\nRsacStLCR1jUc6EzaCaj61w=\n-----END PRIVATE KEY-----\n",
		#   "client_email": "some-service-account@some-project-id.iam.gserviceaccount.com",
		#   "client_id": "some-client-id",
		#   "auth_uri": "https://accounts.google.com/o/oauth2/auth",
		#   "token_uri": "https://oauth2.googleapis.com/token",
		#   "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		#   "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com"
		# }`,
		},
		{
			name: "Commented_out_JSON_(slashes)",
			input: `// {
		//   "type": "service_account",
		//   "project_id": "some-project-id",
		//   "private_key_id": "123456789abcdef0123456789abcdef012345678",
		//   "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\nRsacStLCR1jUc6EzaCaj61w=\n-----END PRIVATE KEY-----\n",
		//   "client_email": "some-service-account@some-project-id.iam.gserviceaccount.com",
		//   "client_id": "some-client-id",
		//   "auth_uri": "https://accounts.google.com/o/oauth2/auth",
		//   "token_uri": "https://oauth2.googleapis.com/token",
		//   "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		//   "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com"
		// }`,
		},
		{
			name:  "Base64 (pretty JSON)",
			input: `ewogICJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIsCiAgInByb2plY3RfaWQiOiAic29tZS1wcm9qZWN0LWlkIiwKICAicHJpdmF0ZV9rZXlfaWQiOiAiMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3OCIsCiAgInByaXZhdGVfa2V5IjogIi0tLS0tQkVHSU4gUFJJVkFURSBLRVktLS0tLVxuTUlJRXZRSUJBREFOQmdrcWhraUc5dzBCQVFFRkFBU0NCS2N3Z2dTakFnRUFBb0lCQVFDc1FmUTUyNGpTQ3RBaVxuMFJield1bzNTNmpKalR5ZFllU08vY0tvdUVPbWhLTG9VeFdWRVhHQzcwTUZML2VkNVhxcFI4MmFtSlp3enhMTlxudFdRQUJ3TEdMa2ZENGFENE1BV3ByU2pSQXY5WVNVSTVzK05qaXFncHpOdWx5c2dRbUtEeTN6Z3E0Y0FRdEt6blxualdnWmpNclhWUXoxVWhSWkFpTy94RGIveDZzdy80RE1KcHR3MnpIdnh4TW5SUi9vOTNVTStmeUo2TDk5VU5oQ1xuekxJcDlJVDhKUUVoUXU2OFBiZ3JodTA0c3lyVU9ZUHJXTHRwQ0RjODBoUFc5QS9VSmlXWWtaY3hoSFNFWHRzTlxuZE5HbEI1UytqSUVaRHF5TGFIUkoydmF1ZDVDRWQ4Q1RSUGhJTTFBU25qMzYrRnlRQTJZUmFGdkpvZnc3Nk4xV1xuSjlCTXJKYWRBZ01CQUFFQ2dnRUFDdjFHTEc3Q0FzeG56T0RUK3dDQTByaEQ4MS9NVHlvUW44SzJxWGJmOGY2aVxuT2ZvYTlXQ2dnajdyWXFoVnZzQUdIRWlWYUZoMXVJcXRZMnhBRGZSa2krb2w3K3cwRGNGYWl5R2Q2ZityOUtEdlxuMWFpUlNDZHZaUU5KdkFEODFIbzRRbVpWT2Y4ZTlySGdHZ0dlYzRyVTRmbnVFclNDMGM3ZUl2ek1tWExPakJpVlxuM2NoOUNITzdpS3Awa3JMZnNTbkFIbkszb3ZlNWtHQkE2QTNzWXdSKy83NjgwaS9hb0M3bDNndFhoME1XMkU5aFxua2tMS2M5VnFaZW5yTWxYb01RbmdJNmMwSWkvQW50UWJiM2Frb21ucWxhaklhME9pYkJMWVRKYnYyNkNoVWxzTlxuQTZTR1FISVhlbU0rSHVpQWgvVTZBQXZsWGtUU0dRc083OGZFdHd2QzdRS0JnUURubE5JVDNDa3FUbWV2K3Arb1xuUjM0Um1UL2MrOE5MQ1V2OHJkQnRVTkVyWTQveS9MYWdnMG9xNm5QdS9wK0tMblM3M3ljR2hzU0JVYkFjOCt3eVxub0VneTRCNGU5Mmp6bTBOeEZ2OGkzY1kyOU80cXh0bjk5a2ZLcmZzY3NNY3F5Y3B4YmRvVHBQZ1J5aEZHc0lUdVxuWjhsQnFGRFVVbGNvd0VOdUptRG5OYlF3NHdLQmdRQythOGcwQWFNSGkzUUJ6MjJLZkxXZTlIRHk4RGF3WS96eFxuSGFqb28rL2E1YzhCT2wyWldUK1lkblFSV3N2cjM3MHlQY1NOV2tnNk53bW1TeDFERjNQVHBSVGlJVUZhNmF6QlxubTdhRXhZSFhTdW1WVXNEcW11MlRETVJWQndiNmxDUVNUWTBReVN3dmYyM2tQVCthZFlOdnRMZHZWTjZzTHB3d1xubnI0ZjF4UXlmd0tCZ1FDazVFcFE2Y3BGM1YzbTU4VVd4UkQyNXUrYUlZbUV2REhtMEx3L21mUFZ1U2FlRldMVVxuRjZlUHR6Q2xVNWUxaEM2S052SktxMXJ2MllKVW16bnJNa1UyTkc0K0Rsd2tXTUZFbk9NOXFEdWlsZk9mY2NkMlxuRlE0NU9uZzZqWVRDNnJ2QzJEMFhEN2V5c3ZacUp2WC82dFphY2NaYjUrVTNsdTVzVjlkWHlkMXJrUUtCZ0I1aFxuWTllb1N6Snc5VmswbHUxNWFDQ3NMemtUU2lacVRYakttcUJEUjRsTkVQSEpOaFc1UDRRN29ka0MrM1h1aEdqM1xub2R4TGd5cUdqV3VTb0dDTDVWYm5CNlhzV0ZrQTN5Y2tpTUkySUxrUW9xUElTQzhsK0xGMVgvMlEyWFF4SG5BdFxuSDB5R1RCNW4za2lEM1JudmxjREV2Rjl1MHZmMWw4WEtEZHRXblVwUkFvR0FQZVJ2QkdzVFhEMGM2MkZBUTdDdFxuSDdlN0lscVMwaUtmUlY1L2NtVURldUZEOFJCSzRpWkZUbENBVnFha2RtalVsZkpQYjYwRDN4d2xKcENvWlNLaVxuMmxZOVJqN3lwUmlUVW9UMzVuVlZIdzhlandZQk1hd280R2thcWQxOThtWXhVb2dKdk91VGNHSjUwOURkVGFja1xuUnNhY1N0TENSMWpVYzZFemFDYWo2MXc9XG4tLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tXG4iLAogICJjbGllbnRfZW1haWwiOiAic29tZS1zZXJ2aWNlLWFjY291bnRAc29tZS1wcm9qZWN0LWlkLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwKICAiY2xpZW50X2lkIjogInNvbWUtY2xpZW50LWlkIiwKICAiYXV0aF91cmkiOiAiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tL28vb2F1dGgyL2F1dGgiLAogICJ0b2tlbl91cmkiOiAiaHR0cHM6Ly9vYXV0aDIuZ29vZ2xlYXBpcy5jb20vdG9rZW4iLAogICJhdXRoX3Byb3ZpZGVyX3g1MDlfY2VydF91cmwiOiAiaHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vb2F1dGgyL3YxL2NlcnRzIiwKICAiY2xpZW50X3g1MDlfY2VydF91cmwiOiAiaHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vcm9ib3QvdjEvbWV0YWRhdGEveDUwOS9zb21lLXNlcnZpY2UtYWNjb3VudCU0MHNvbWUtcHJvamVjdC1pZC5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbSIKfQ==`,
		},
		{
			name:  "Base64 (pretty JSON) - nested",
			input: `{"Key":"ewogICJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIsCiAgInByb2plY3RfaWQiOiAic29tZS1wcm9qZWN0LWlkIiwKICAicHJpdmF0ZV9rZXlfaWQiOiAiMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3OCIsCiAgInByaXZhdGVfa2V5IjogIi0tLS0tQkVHSU4gUFJJVkFURSBLRVktLS0tLVxuTUlJRXZRSUJBREFOQmdrcWhraUc5dzBCQVFFRkFBU0NCS2N3Z2dTakFnRUFBb0lCQVFDc1FmUTUyNGpTQ3RBaVxuMFJield1bzNTNmpKalR5ZFllU08vY0tvdUVPbWhLTG9VeFdWRVhHQzcwTUZML2VkNVhxcFI4MmFtSlp3enhMTlxudFdRQUJ3TEdMa2ZENGFENE1BV3ByU2pSQXY5WVNVSTVzK05qaXFncHpOdWx5c2dRbUtEeTN6Z3E0Y0FRdEt6blxualdnWmpNclhWUXoxVWhSWkFpTy94RGIveDZzdy80RE1KcHR3MnpIdnh4TW5SUi9vOTNVTStmeUo2TDk5VU5oQ1xuekxJcDlJVDhKUUVoUXU2OFBiZ3JodTA0c3lyVU9ZUHJXTHRwQ0RjODBoUFc5QS9VSmlXWWtaY3hoSFNFWHRzTlxuZE5HbEI1UytqSUVaRHF5TGFIUkoydmF1ZDVDRWQ4Q1RSUGhJTTFBU25qMzYrRnlRQTJZUmFGdkpvZnc3Nk4xV1xuSjlCTXJKYWRBZ01CQUFFQ2dnRUFDdjFHTEc3Q0FzeG56T0RUK3dDQTByaEQ4MS9NVHlvUW44SzJxWGJmOGY2aVxuT2ZvYTlXQ2dnajdyWXFoVnZzQUdIRWlWYUZoMXVJcXRZMnhBRGZSa2krb2w3K3cwRGNGYWl5R2Q2ZityOUtEdlxuMWFpUlNDZHZaUU5KdkFEODFIbzRRbVpWT2Y4ZTlySGdHZ0dlYzRyVTRmbnVFclNDMGM3ZUl2ek1tWExPakJpVlxuM2NoOUNITzdpS3Awa3JMZnNTbkFIbkszb3ZlNWtHQkE2QTNzWXdSKy83NjgwaS9hb0M3bDNndFhoME1XMkU5aFxua2tMS2M5VnFaZW5yTWxYb01RbmdJNmMwSWkvQW50UWJiM2Frb21ucWxhaklhME9pYkJMWVRKYnYyNkNoVWxzTlxuQTZTR1FISVhlbU0rSHVpQWgvVTZBQXZsWGtUU0dRc083OGZFdHd2QzdRS0JnUURubE5JVDNDa3FUbWV2K3Arb1xuUjM0Um1UL2MrOE5MQ1V2OHJkQnRVTkVyWTQveS9MYWdnMG9xNm5QdS9wK0tMblM3M3ljR2hzU0JVYkFjOCt3eVxub0VneTRCNGU5Mmp6bTBOeEZ2OGkzY1kyOU80cXh0bjk5a2ZLcmZzY3NNY3F5Y3B4YmRvVHBQZ1J5aEZHc0lUdVxuWjhsQnFGRFVVbGNvd0VOdUptRG5OYlF3NHdLQmdRQythOGcwQWFNSGkzUUJ6MjJLZkxXZTlIRHk4RGF3WS96eFxuSGFqb28rL2E1YzhCT2wyWldUK1lkblFSV3N2cjM3MHlQY1NOV2tnNk53bW1TeDFERjNQVHBSVGlJVUZhNmF6QlxubTdhRXhZSFhTdW1WVXNEcW11MlRETVJWQndiNmxDUVNUWTBReVN3dmYyM2tQVCthZFlOdnRMZHZWTjZzTHB3d1xubnI0ZjF4UXlmd0tCZ1FDazVFcFE2Y3BGM1YzbTU4VVd4UkQyNXUrYUlZbUV2REhtMEx3L21mUFZ1U2FlRldMVVxuRjZlUHR6Q2xVNWUxaEM2S052SktxMXJ2MllKVW16bnJNa1UyTkc0K0Rsd2tXTUZFbk9NOXFEdWlsZk9mY2NkMlxuRlE0NU9uZzZqWVRDNnJ2QzJEMFhEN2V5c3ZacUp2WC82dFphY2NaYjUrVTNsdTVzVjlkWHlkMXJrUUtCZ0I1aFxuWTllb1N6Snc5VmswbHUxNWFDQ3NMemtUU2lacVRYakttcUJEUjRsTkVQSEpOaFc1UDRRN29ka0MrM1h1aEdqM1xub2R4TGd5cUdqV3VTb0dDTDVWYm5CNlhzV0ZrQTN5Y2tpTUkySUxrUW9xUElTQzhsK0xGMVgvMlEyWFF4SG5BdFxuSDB5R1RCNW4za2lEM1JudmxjREV2Rjl1MHZmMWw4WEtEZHRXblVwUkFvR0FQZVJ2QkdzVFhEMGM2MkZBUTdDdFxuSDdlN0lscVMwaUtmUlY1L2NtVURldUZEOFJCSzRpWkZUbENBVnFha2RtalVsZkpQYjYwRDN4d2xKcENvWlNLaVxuMmxZOVJqN3lwUmlUVW9UMzVuVlZIdzhlandZQk1hd280R2thcWQxOThtWXhVb2dKdk91VGNHSjUwOURkVGFja1xuUnNhY1N0TENSMWpVYzZFemFDYWo2MXc9XG4tLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tXG4iLAogICJjbGllbnRfZW1haWwiOiAic29tZS1zZXJ2aWNlLWFjY291bnRAc29tZS1wcm9qZWN0LWlkLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwKICAiY2xpZW50X2lkIjogInNvbWUtY2xpZW50LWlkIiwKICAiYXV0aF91cmkiOiAiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tL28vb2F1dGgyL2F1dGgiLAogICJ0b2tlbl91cmkiOiAiaHR0cHM6Ly9vYXV0aDIuZ29vZ2xlYXBpcy5jb20vdG9rZW4iLAogICJhdXRoX3Byb3ZpZGVyX3g1MDlfY2VydF91cmwiOiAiaHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vb2F1dGgyL3YxL2NlcnRzIiwKICAiY2xpZW50X3g1MDlfY2VydF91cmwiOiAiaHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vcm9ib3QvdjEvbWV0YWRhdGEveDUwOS9zb21lLXNlcnZpY2UtYWNjb3VudCU0MHNvbWUtcHJvamVjdC1pZC5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbSIKfQ=="}`,
		},
		{
			name: "Python_dict_(double_quotes)",
			input: `{
			"type": "service_account",
			"project_id": "some-project-id",
			"private_key_id": "123456789abcdef0123456789abcdef012345678",
			"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\nRsacStLCR1jUc6EzaCaj61w=\n-----END PRIVATE KEY-----\n",
			"client_email": "some-service-account@some-project-id.iam.gserviceaccount.com",
			"client_id": "some-client-id",
			"auth_uri": "https://accounts.google.com/o/oauth2/auth",
			"token_uri": "https://oauth2.googleapis.com/token",
			"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
			"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com",
		}`,
		},
		{
			name: "IPython",
			input: `"source": [
				"{\n",
				"  \"type\": \"service_account\",\n",
				"  \"project_id\": \"some-project-id\",\n",
				"  \"private_key_id\": \"123456789abcdef0123456789abcdef012345678\",\n",
				"  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\\nRsacStLCR1jUc6EzaCaj61w=\\n-----END PRIVATE KEY-----\\n\",\n",
				"  \"client_email\": \"some-service-account@some-project-id.iam.gserviceaccount.com\",\n",
				"  \"client_id\": \"some-client-id\",\n",
				"  \"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\",\n",
				"  \"token_uri\": \"https://oauth2.googleapis.com/token\",\n",
				"  \"auth_provider_x509_cert_url\": \"https://www.googleapis.com/oauth2/v1/certs\",\n",
				"  \"client_x509_cert_url\": \"https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com\"\n",
				"}",
		],`,
		},
		{
			name: "C-style_multiline_string",
			input: `const char *key = 
			"{"
			"  \"type\": \"service_account\","
			"  \"project_id\": \"some-project-id\","
			"  \"private_key_id\": \"123456789abcdef0123456789abcdef012345678\","
			"  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\\nRsacStLCR1jUc6EzaCaj61w=\\n-----END PRIVATE KEY-----\\n\","
			"  \"client_email\": \"some-service-account@some-project-id.iam.gserviceaccount.com\","
			"  \"client_id\": \"some-client-id\","
			"  \"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\","
			"  \"token_uri\": \"https://oauth2.googleapis.com/token\","
			"  \"auth_provider_x509_cert_url\": \"https://www.googleapis.com/oauth2/v1/certs\","
			"  \"client_x509_cert_url\": \"https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com\""
			"}";`,
		},
		{
			name: "Alternative_Python_multiline_string",
			input: `key = '' \
				'{\n' \
				'  "type": "service_account",\n' \
				'  "project_id": "some-project-id",\n' \
				'  "private_key_id": "123456789abcdef0123456789abcdef012345678",\n' \
				'  "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\\nRsacStLCR1jUc6EzaCaj61w=\\n-----END PRIVATE KEY-----\\n",\n' \
				'  "client_email": "some-service-account@some-project-id.iam.gserviceaccount.com",\n' \
				'  "client_id": "some-client-id",\n' \
				'  "auth_uri": "https://accounts.google.com/o/oauth2/auth",\n' \
				'  "token_uri": "https://oauth2.googleapis.com/token",\n' \
				'  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",\n' \
				'  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com"\n' \
				'}'`,
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			t.Parallel()
			engine, err := veles.NewDetectionEngine([]veles.Detector{scenario.detector})
			if err != nil {
				t.Errorf("veles.NewDetectionEngine() error: %v", err)
			}
			want := scenario.want
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()
					got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
					if err != nil {
						t.Errorf("Detect() error: %v, want nil", err)
					}
					if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
						t.Errorf("Detect() diff (-want +got):\n%s", diff)
					}
				})
			}
		})
	}
}

// TestDetector_trueNegatives tests for cases where we know the Detector
// won't show a false positive that other secret scanners might.
func TestDetector_trueNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{gcpsak.NewDetector()})
	if err != nil {
		t.Errorf("veles.NewDetectionEngine() error: %v", err)
	}
	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "empty input",
			input: "",
		},
		{
			// If a scanner were to use "auth_provider_x509_cert_url" as a hotword and
			// then rely on Go's permissive JSON parsing to extract the key, it could
			// surface this as a false positive.
			name: "OAuth2_token",
			input: `{
				"installed": {
					"client_id": "this-should-not-be-a-real-app.apps.googleusercontent.com",
					"project_id": "some-project",
					"auth_uri": "https://accounts.google.com/o/oauth2/auth",
					"token_uri": "https://oauth2.googleapis.com/token",
					"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
					"client_secret": "GOCSPX-FOO_BARBARBAR7_1234567890a",
					"redirect_uris": ["http://localhost"]
				}
			}`,
		},
	}
	var want []veles.Secret
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDetector_falseNegatives explicitly lists and tests for cases where we
// know the Detector won't find a GCP SAK.
func TestDetector_falseNegatives(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{gcpsak.NewDetector()})
	if err != nil {
		t.Errorf("veles.NewDetectionEngine() error: %v", err)
	}
	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "Base64 (pretty JSON, sorted)",
			input: `ewogICJhdXRoX3Byb3ZpZGVyX3g1MDlfY2VydF91cmwiOiAiaHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vb2F1dGgyL3YxL2NlcnRzIiwKICAiYXV0aF91cmkiOiAiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tL28vb2F1dGgyL2F1dGgiLAogICJjbGllbnRfZW1haWwiOiAic29tZS1zZXJ2aWNlLWFjY291bnRAc29tZS1wcm9qZWN0LWlkLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwKICAiY2xpZW50X2lkIjogInNvbWUtY2xpZW50LWlkIiwKICAiY2xpZW50X3g1MDlfY2VydF91cmwiOiAiaHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vcm9ib3QvdjEvbWV0YWRhdGEveDUwOS9zb21lLXNlcnZpY2UtYWNjb3VudCU0MHNvbWUtcHJvamVjdC1pZC5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbSIsCiAgInByaXZhdGVfa2V5IjogIi0tLS0tQkVHSU4gUFJJVkFURSBLRVktLS0tLVxuTUlJRXZRSUJBREFOQmdrcWhraUc5dzBCQVFFRkFBU0NCS2N3Z2dTakFnRUFBb0lCQVFDc1FmUTUyNGpTQ3RBaVxuMFJield1bzNTNmpKalR5ZFllU08vY0tvdUVPbWhLTG9VeFdWRVhHQzcwTUZML2VkNVhxcFI4MmFtSlp3enhMTlxudFdRQUJ3TEdMa2ZENGFENE1BV3ByU2pSQXY5WVNVSTVzK05qaXFncHpOdWx5c2dRbUtEeTN6Z3E0Y0FRdEt6blxualdnWmpNclhWUXoxVWhSWkFpTy94RGIveDZzdy80RE1KcHR3MnpIdnh4TW5SUi9vOTNVTStmeUo2TDk5VU5oQ1xuekxJcDlJVDhKUUVoUXU2OFBiZ3JodTA0c3lyVU9ZUHJXTHRwQ0RjODBoUFc5QS9VSmlXWWtaY3hoSFNFWHRzTlxuZE5HbEI1UytqSUVaRHF5TGFIUkoydmF1ZDVDRWQ4Q1RSUGhJTTFBU25qMzYrRnlRQTJZUmFGdkpvZnc3Nk4xV1xuSjlCTXJKYWRBZ01CQUFFQ2dnRUFDdjFHTEc3Q0FzeG56T0RUK3dDQTByaEQ4MS9NVHlvUW44SzJxWGJmOGY2aVxuT2ZvYTlXQ2dnajdyWXFoVnZzQUdIRWlWYUZoMXVJcXRZMnhBRGZSa2krb2w3K3cwRGNGYWl5R2Q2ZityOUtEdlxuMWFpUlNDZHZaUU5KdkFEODFIbzRRbVpWT2Y4ZTlySGdHZ0dlYzRyVTRmbnVFclNDMGM3ZUl2ek1tWExPakJpVlxuM2NoOUNITzdpS3Awa3JMZnNTbkFIbkszb3ZlNWtHQkE2QTNzWXdSKy83NjgwaS9hb0M3bDNndFhoME1XMkU5aFxua2tMS2M5VnFaZW5yTWxYb01RbmdJNmMwSWkvQW50UWJiM2Frb21ucWxhaklhME9pYkJMWVRKYnYyNkNoVWxzTlxuQTZTR1FISVhlbU0rSHVpQWgvVTZBQXZsWGtUU0dRc083OGZFdHd2QzdRS0JnUURubE5JVDNDa3FUbWV2K3Arb1xuUjM0Um1UL2MrOE5MQ1V2OHJkQnRVTkVyWTQveS9MYWdnMG9xNm5QdS9wK0tMblM3M3ljR2hzU0JVYkFjOCt3eVxub0VneTRCNGU5Mmp6bTBOeEZ2OGkzY1kyOU80cXh0bjk5a2ZLcmZzY3NNY3F5Y3B4YmRvVHBQZ1J5aEZHc0lUdVxuWjhsQnFGRFVVbGNvd0VOdUptRG5OYlF3NHdLQmdRQythOGcwQWFNSGkzUUJ6MjJLZkxXZTlIRHk4RGF3WS96eFxuSGFqb28rL2E1YzhCT2wyWldUK1lkblFSV3N2cjM3MHlQY1NOV2tnNk53bW1TeDFERjNQVHBSVGlJVUZhNmF6QlxubTdhRXhZSFhTdW1WVXNEcW11MlRETVJWQndiNmxDUVNUWTBReVN3dmYyM2tQVCthZFlOdnRMZHZWTjZzTHB3d1xubnI0ZjF4UXlmd0tCZ1FDazVFcFE2Y3BGM1YzbTU4VVd4UkQyNXUrYUlZbUV2REhtMEx3L21mUFZ1U2FlRldMVVxuRjZlUHR6Q2xVNWUxaEM2S052SktxMXJ2MllKVW16bnJNa1UyTkc0K0Rsd2tXTUZFbk9NOXFEdWlsZk9mY2NkMlxuRlE0NU9uZzZqWVRDNnJ2QzJEMFhEN2V5c3ZacUp2WC82dFphY2NaYjUrVTNsdTVzVjlkWHlkMXJrUUtCZ0I1aFxuWTllb1N6Snc5VmswbHUxNWFDQ3NMemtUU2lacVRYakttcUJEUjRsTkVQSEpOaFc1UDRRN29ka0MrM1h1aEdqM1xub2R4TGd5cUdqV3VTb0dDTDVWYm5CNlhzV0ZrQTN5Y2tpTUkySUxrUW9xUElTQzhsK0xGMVgvMlEyWFF4SG5BdFxuSDB5R1RCNW4za2lEM1JudmxjREV2Rjl1MHZmMWw4WEtEZHRXblVwUkFvR0FQZVJ2QkdzVFhEMGM2MkZBUTdDdFxuSDdlN0lscVMwaUtmUlY1L2NtVURldUZEOFJCSzRpWkZUbENBVnFha2RtalVsZkpQYjYwRDN4d2xKcENvWlNLaVxuMmxZOVJqN3lwUmlUVW9UMzVuVlZIdzhlandZQk1hd280R2thcWQxOThtWXhVb2dKdk91VGNHSjUwOURkVGFja1xuUnNhY1N0TENSMWpVYzZFemFDYWo2MXc9XG4tLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tXG4iLAogICJwcml2YXRlX2tleV9pZCI6ICIxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4IiwKICAicHJvamVjdF9pZCI6ICJzb21lLXByb2plY3QtaWQiLAogICJ0b2tlbl91cmkiOiAiaHR0cHM6Ly9vYXV0aDIuZ29vZ2xlYXBpcy5jb20vdG9rZW4iLAogICJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIKfQ==`,
		},
		{
			name:  "Base64 (flat JSON)",
			input: `eyJ0eXBlIjoic2VydmljZV9hY2NvdW50IiwicHJvamVjdF9pZCI6InNvbWUtcHJvamVjdC1pZCIsInByaXZhdGVfa2V5X2lkIjoiMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3OCIsInByaXZhdGVfa2V5IjoiLS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tXG5NSUlFdlFJQkFEQU5CZ2txaGtpRzl3MEJBUUVGQUFTQ0JLY3dnZ1NqQWdFQUFvSUJBUUNzUWZRNTI0alNDdEFpXG4wUmJ6V3VvM1M2akpqVHlkWWVTTy9jS291RU9taEtMb1V4V1ZFWEdDNzBNRkwvZWQ1WHFwUjgyYW1KWnd6eExOXG50V1FBQndMR0xrZkQ0YUQ0TUFXcHJTalJBdjlZU1VJNXMrTmppcWdwek51bHlzZ1FtS0R5M3pncTRjQVF0S3puXG5qV2daak1yWFZRejFVaFJaQWlPL3hEYi94NnN3LzRETUpwdHcyekh2eHhNblJSL285M1VNK2Z5SjZMOTlVTmhDXG56TElwOUlUOEpRRWhRdTY4UGJncmh1MDRzeXJVT1lQcldMdHBDRGM4MGhQVzlBL1VKaVdZa1pjeGhIU0VYdHNOXG5kTkdsQjVTK2pJRVpEcXlMYUhSSjJ2YXVkNUNFZDhDVFJQaElNMUFTbmozNitGeVFBMllSYUZ2Sm9mdzc2TjFXXG5KOUJNckphZEFnTUJBQUVDZ2dFQUN2MUdMRzdDQXN4bnpPRFQrd0NBMHJoRDgxL01UeW9RbjhLMnFYYmY4ZjZpXG5PZm9hOVdDZ2dqN3JZcWhWdnNBR0hFaVZhRmgxdUlxdFkyeEFEZlJraStvbDcrdzBEY0ZhaXlHZDZmK3I5S0R2XG4xYWlSU0NkdlpRTkp2QUQ4MUhvNFFtWlZPZjhlOXJIZ0dnR2VjNHJVNGZudUVyU0MwYzdlSXZ6TW1YTE9qQmlWXG4zY2g5Q0hPN2lLcDBrckxmc1NuQUhuSzNvdmU1a0dCQTZBM3NZd1IrLzc2ODBpL2FvQzdsM2d0WGgwTVcyRTloXG5ra0xLYzlWcVplbnJNbFhvTVFuZ0k2YzBJaS9BbnRRYmIzYWtvbW5xbGFqSWEwT2liQkxZVEpidjI2Q2hVbHNOXG5BNlNHUUhJWGVtTStIdWlBaC9VNkFBdmxYa1RTR1FzTzc4ZkV0d3ZDN1FLQmdRRG5sTklUM0NrcVRtZXYrcCtvXG5SMzRSbVQvYys4TkxDVXY4cmRCdFVORXJZNC95L0xhZ2cwb3E2blB1L3ArS0xuUzczeWNHaHNTQlViQWM4K3d5XG5vRWd5NEI0ZTkyanptME54RnY4aTNjWTI5TzRxeHRuOTlrZktyZnNjc01jcXljcHhiZG9UcFBnUnloRkdzSVR1XG5aOGxCcUZEVVVsY293RU51Sm1Ebk5iUXc0d0tCZ1FDK2E4ZzBBYU1IaTNRQnoyMktmTFdlOUhEeThEYXdZL3p4XG5IYWpvbysvYTVjOEJPbDJaV1QrWWRuUVJXc3ZyMzcweVBjU05Xa2c2TndtbVN4MURGM1BUcFJUaUlVRmE2YXpCXG5tN2FFeFlIWFN1bVZVc0RxbXUyVERNUlZCd2I2bENRU1RZMFF5U3d2ZjIza1BUK2FkWU52dExkdlZONnNMcHd3XG5ucjRmMXhReWZ3S0JnUUNrNUVwUTZjcEYzVjNtNThVV3hSRDI1dSthSVltRXZESG0wTHcvbWZQVnVTYWVGV0xVXG5GNmVQdHpDbFU1ZTFoQzZLTnZKS3ExcnYyWUpVbXpuck1rVTJORzQrRGx3a1dNRkVuT005cUR1aWxmT2ZjY2QyXG5GUTQ1T25nNmpZVEM2cnZDMkQwWEQ3ZXlzdlpxSnZYLzZ0WmFjY1piNStVM2x1NXNWOWRYeWQxcmtRS0JnQjVoXG5ZOWVvU3pKdzlWazBsdTE1YUNDc0x6a1RTaVpxVFhqS21xQkRSNGxORVBISk5oVzVQNFE3b2RrQyszWHVoR2ozXG5vZHhMZ3lxR2pXdVNvR0NMNVZibkI2WHNXRmtBM3lja2lNSTJJTGtRb3FQSVNDOGwrTEYxWC8yUTJYUXhIbkF0XG5IMHlHVEI1bjNraUQzUm52bGNERXZGOXUwdmYxbDhYS0RkdFduVXBSQW9HQVBlUnZCR3NUWEQwYzYyRkFRN0N0XG5IN2U3SWxxUzBpS2ZSVjUvY21VRGV1RkQ4UkJLNGlaRlRsQ0FWcWFrZG1qVWxmSlBiNjBEM3h3bEpwQ29aU0tpXG4ybFk5Umo3eXBSaVRVb1QzNW5WVkh3OGVqd1lCTWF3bzRHa2FxZDE5OG1ZeFVvZ0p2T3VUY0dKNTA5RGRUYWNrXG5Sc2FjU3RMQ1IxalVjNkV6YUNhajYxdz1cbi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS1cbiIsImNsaWVudF9lbWFpbCI6InNvbWUtc2VydmljZS1hY2NvdW50QHNvbWUtcHJvamVjdC1pZC5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbSIsImNsaWVudF9pZCI6InNvbWUtY2xpZW50LWlkIiwiYXV0aF91cmkiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20vby9vYXV0aDIvYXV0aCIsInRva2VuX3VyaSI6Imh0dHBzOi8vb2F1dGgyLmdvb2dsZWFwaXMuY29tL3Rva2VuIiwiYXV0aF9wcm92aWRlcl94NTA5X2NlcnRfdXJsIjoiaHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vb2F1dGgyL3YxL2NlcnRzIiwiY2xpZW50X3g1MDlfY2VydF91cmwiOiJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9yb2JvdC92MS9tZXRhZGF0YS94NTA5L3NvbWUtc2VydmljZS1hY2NvdW50JTQwc29tZS1wcm9qZWN0LWlkLmlhbS5nc2VydmljZWFjY291bnQuY29tIn0=`,
		},
		{
			name:  "Base64 (different whitespace)",
			input: `ewoJInR5cGUiOiAic2VydmljZV9hY2NvdW50IiwKCSJwcm9qZWN0X2lkIjogInNvbWUtcHJvamVjdC1pZCIsCgkicHJpdmF0ZV9rZXlfaWQiOiAiMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3OCIsCgkicHJpdmF0ZV9rZXkiOiAiLS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tXG5NSUlFdlFJQkFEQU5CZ2txaGtpRzl3MEJBUUVGQUFTQ0JLY3dnZ1NqQWdFQUFvSUJBUUNzUWZRNTI0alNDdEFpXG4wUmJ6V3VvM1M2akpqVHlkWWVTTy9jS291RU9taEtMb1V4V1ZFWEdDNzBNRkwvZWQ1WHFwUjgyYW1KWnd6eExOXG50V1FBQndMR0xrZkQ0YUQ0TUFXcHJTalJBdjlZU1VJNXMrTmppcWdwek51bHlzZ1FtS0R5M3pncTRjQVF0S3puXG5qV2daak1yWFZRejFVaFJaQWlPL3hEYi94NnN3LzRETUpwdHcyekh2eHhNblJSL285M1VNK2Z5SjZMOTlVTmhDXG56TElwOUlUOEpRRWhRdTY4UGJncmh1MDRzeXJVT1lQcldMdHBDRGM4MGhQVzlBL1VKaVdZa1pjeGhIU0VYdHNOXG5kTkdsQjVTK2pJRVpEcXlMYUhSSjJ2YXVkNUNFZDhDVFJQaElNMUFTbmozNitGeVFBMllSYUZ2Sm9mdzc2TjFXXG5KOUJNckphZEFnTUJBQUVDZ2dFQUN2MUdMRzdDQXN4bnpPRFQrd0NBMHJoRDgxL01UeW9RbjhLMnFYYmY4ZjZpXG5PZm9hOVdDZ2dqN3JZcWhWdnNBR0hFaVZhRmgxdUlxdFkyeEFEZlJraStvbDcrdzBEY0ZhaXlHZDZmK3I5S0R2XG4xYWlSU0NkdlpRTkp2QUQ4MUhvNFFtWlZPZjhlOXJIZ0dnR2VjNHJVNGZudUVyU0MwYzdlSXZ6TW1YTE9qQmlWXG4zY2g5Q0hPN2lLcDBrckxmc1NuQUhuSzNvdmU1a0dCQTZBM3NZd1IrLzc2ODBpL2FvQzdsM2d0WGgwTVcyRTloXG5ra0xLYzlWcVplbnJNbFhvTVFuZ0k2YzBJaS9BbnRRYmIzYWtvbW5xbGFqSWEwT2liQkxZVEpidjI2Q2hVbHNOXG5BNlNHUUhJWGVtTStIdWlBaC9VNkFBdmxYa1RTR1FzTzc4ZkV0d3ZDN1FLQmdRRG5sTklUM0NrcVRtZXYrcCtvXG5SMzRSbVQvYys4TkxDVXY4cmRCdFVORXJZNC95L0xhZ2cwb3E2blB1L3ArS0xuUzczeWNHaHNTQlViQWM4K3d5XG5vRWd5NEI0ZTkyanptME54RnY4aTNjWTI5TzRxeHRuOTlrZktyZnNjc01jcXljcHhiZG9UcFBnUnloRkdzSVR1XG5aOGxCcUZEVVVsY293RU51Sm1Ebk5iUXc0d0tCZ1FDK2E4ZzBBYU1IaTNRQnoyMktmTFdlOUhEeThEYXdZL3p4XG5IYWpvbysvYTVjOEJPbDJaV1QrWWRuUVJXc3ZyMzcweVBjU05Xa2c2TndtbVN4MURGM1BUcFJUaUlVRmE2YXpCXG5tN2FFeFlIWFN1bVZVc0RxbXUyVERNUlZCd2I2bENRU1RZMFF5U3d2ZjIza1BUK2FkWU52dExkdlZONnNMcHd3XG5ucjRmMXhReWZ3S0JnUUNrNUVwUTZjcEYzVjNtNThVV3hSRDI1dSthSVltRXZESG0wTHcvbWZQVnVTYWVGV0xVXG5GNmVQdHpDbFU1ZTFoQzZLTnZKS3ExcnYyWUpVbXpuck1rVTJORzQrRGx3a1dNRkVuT005cUR1aWxmT2ZjY2QyXG5GUTQ1T25nNmpZVEM2cnZDMkQwWEQ3ZXlzdlpxSnZYLzZ0WmFjY1piNStVM2x1NXNWOWRYeWQxcmtRS0JnQjVoXG5ZOWVvU3pKdzlWazBsdTE1YUNDc0x6a1RTaVpxVFhqS21xQkRSNGxORVBISk5oVzVQNFE3b2RrQyszWHVoR2ozXG5vZHhMZ3lxR2pXdVNvR0NMNVZibkI2WHNXRmtBM3lja2lNSTJJTGtRb3FQSVNDOGwrTEYxWC8yUTJYUXhIbkF0XG5IMHlHVEI1bjNraUQzUm52bGNERXZGOXUwdmYxbDhYS0RkdFduVXBSQW9HQVBlUnZCR3NUWEQwYzYyRkFRN0N0XG5IN2U3SWxxUzBpS2ZSVjUvY21VRGV1RkQ4UkJLNGlaRlRsQ0FWcWFrZG1qVWxmSlBiNjBEM3h3bEpwQ29aU0tpXG4ybFk5Umo3eXBSaVRVb1QzNW5WVkh3OGVqd1lCTWF3bzRHa2FxZDE5OG1ZeFVvZ0p2T3VUY0dKNTA5RGRUYWNrXG5Sc2FjU3RMQ1IxalVjNkV6YUNhajYxdz1cbi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS1cbiIsCgkiY2xpZW50X2VtYWlsIjogInNvbWUtc2VydmljZS1hY2NvdW50QHNvbWUtcHJvamVjdC1pZC5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbSIsCgkiY2xpZW50X2lkIjogInNvbWUtY2xpZW50LWlkIiwKCSJhdXRoX3VyaSI6ICJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20vby9vYXV0aDIvYXV0aCIsCgkidG9rZW5fdXJpIjogImh0dHBzOi8vb2F1dGgyLmdvb2dsZWFwaXMuY29tL3Rva2VuIiwKCSJhdXRoX3Byb3ZpZGVyX3g1MDlfY2VydF91cmwiOiAiaHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vb2F1dGgyL3YxL2NlcnRzIiwKCSJjbGllbnRfeDUwOV9jZXJ0X3VybCI6ICJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9yb2JvdC92MS9tZXRhZGF0YS94NTA5L3NvbWUtc2VydmljZS1hY2NvdW50JTQwc29tZS1wcm9qZWN0LWlkLmlhbS5nc2VydmljZWFjY291bnQuY29tIgp9`,
		},
		{
			name: "Python_dict_(single_quotes)",
			input: `{
			'type': 'service_account',
			'project_id': 'some-project-id',
			'private_key_id': '123456789abcdef0123456789abcdef012345678',
			'private_key': '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\nRsacStLCR1jUc6EzaCaj61w=\n-----END PRIVATE KEY-----\n',
			'client_email': 'some-service-account@some-project-id.iam.gserviceaccount.com',
			'client_id': 'some-client-id',
			'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
			'token_uri': 'https://oauth2.googleapis.com/token',
			'auth_provider_x509_cert_url': 'https://www.googleapis.com/oauth2/v1/certs',
			'client_x509_cert_url': 'https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com',
		}`,
		},
		{
			name: "GCL",
			input: `  service_account = {
				type = 'service_account',
				project_id = 'some-project-id',
				private_key_id = '123456789abcdef0123456789abcdef012345678',
				private_key = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsQfQ524jSCtAi\n0RbzWuo3S6jJjTydYeSO/cKouEOmhKLoUxWVEXGC70MFL/ed5XqpR82amJZwzxLN\ntWQABwLGLkfD4aD4MAWprSjRAv9YSUI5s+NjiqgpzNulysgQmKDy3zgq4cAQtKzn\njWgZjMrXVQz1UhRZAiO/xDb/x6sw/4DMJptw2zHvxxMnRR/o93UM+fyJ6L99UNhC\nzLIp9IT8JQEhQu68Pbgrhu04syrUOYPrWLtpCDc80hPW9A/UJiWYkZcxhHSEXtsN\ndNGlB5S+jIEZDqyLaHRJ2vaud5CEd8CTRPhIM1ASnj36+FyQA2YRaFvJofw76N1W\nJ9BMrJadAgMBAAECggEACv1GLG7CAsxnzODT+wCA0rhD81/MTyoQn8K2qXbf8f6i\nOfoa9WCggj7rYqhVvsAGHEiVaFh1uIqtY2xADfRki+ol7+w0DcFaiyGd6f+r9KDv\n1aiRSCdvZQNJvAD81Ho4QmZVOf8e9rHgGgGec4rU4fnuErSC0c7eIvzMmXLOjBiV\n3ch9CHO7iKp0krLfsSnAHnK3ove5kGBA6A3sYwR+/7680i/aoC7l3gtXh0MW2E9h\nkkLKc9VqZenrMlXoMQngI6c0Ii/AntQbb3akomnqlajIa0OibBLYTJbv26ChUlsN\nA6SGQHIXemM+HuiAh/U6AAvlXkTSGQsO78fEtwvC7QKBgQDnlNIT3CkqTmev+p+o\nR34RmT/c+8NLCUv8rdBtUNErY4/y/Lagg0oq6nPu/p+KLnS73ycGhsSBUbAc8+wy\noEgy4B4e92jzm0NxFv8i3cY29O4qxtn99kfKrfscsMcqycpxbdoTpPgRyhFGsITu\nZ8lBqFDUUlcowENuJmDnNbQw4wKBgQC+a8g0AaMHi3QBz22KfLWe9HDy8DawY/zx\nHajoo+/a5c8BOl2ZWT+YdnQRWsvr370yPcSNWkg6NwmmSx1DF3PTpRTiIUFa6azB\nm7aExYHXSumVUsDqmu2TDMRVBwb6lCQSTY0QySwvf23kPT+adYNvtLdvVN6sLpww\nnr4f1xQyfwKBgQCk5EpQ6cpF3V3m58UWxRD25u+aIYmEvDHm0Lw/mfPVuSaeFWLU\nF6ePtzClU5e1hC6KNvJKq1rv2YJUmznrMkU2NG4+DlwkWMFEnOM9qDuilfOfccd2\nFQ45Ong6jYTC6rvC2D0XD7eysvZqJvX/6tZaccZb5+U3lu5sV9dXyd1rkQKBgB5h\nY9eoSzJw9Vk0lu15aCCsLzkTSiZqTXjKmqBDR4lNEPHJNhW5P4Q7odkC+3XuhGj3\nodxLgyqGjWuSoGCL5VbnB6XsWFkA3yckiMI2ILkQoqPISC8l+LF1X/2Q2XQxHnAt\nH0yGTB5n3kiD3RnvlcDEvF9u0vf1l8XKDdtWnUpRAoGAPeRvBGsTXD0c62FAQ7Ct\nH7e7IlqS0iKfRV5/cmUDeuFD8RBK4iZFTlCAVqakdmjUlfJPb60D3xwlJpCoZSKi\n2lY9Rj7ypRiTUoT35nVVHw8ejwYBMawo4Gkaqd198mYxUogJvOuTcGJ509DdTack\nRsacStLCR1jUc6EzaCaj61w=\n-----END PRIVATE KEY-----\n',
				client_email = 'some-service-account@some-project-id.iam.gserviceaccount.com',
				client_id = 'some-client-id',
				auth_uri = 'https://accounts.google.com/o/oauth2/auth',
				token_uri = 'https://oauth2.googleapis.com/token',
				auth_provider_x509_cert_url = 'https://www.googleapis.com/oauth2/v1/certs',
				client_x509_cert_url = 'https://www.googleapis.com/robot/v1/metadata/x509/some-service-account%40some-project-id.iam.gserviceaccount.com'
			}`,
		},
	}
	var want []veles.Secret
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
