package salesforceoauth2client

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewValidator creates a new Salesforce OAuth Client Credentials Validator.
//
// It performs a POST request to the Salesforce App token endpoint.
// If the request returns HTTP 200, the credentials are valid.
// If 401 Unauthorized, they are invalid.
func NewValidator() *sv.Validator[Credentials] {
	return &sv.Validator[Credentials]{
		EndpointFunc: func(creds Credentials) (string, error) {
			if creds.URL == "" {
				return "", errors.New("URL is empty")
			}
			return fmt.Sprintf("https://%s/services/oauth2/token", creds.URL), nil
		},
		Body: func(creds Credentials) (string, error) {
			// Salesforce requires grant_type in body for client_credentials
			return "grant_type=client_credentials", nil
		},
		HTTPMethod: http.MethodPost,
		HTTPHeaders: func(creds Credentials) map[string]string {
			raw := creds.ID + ":" + creds.Secret
			encoded := base64.StdEncoding.EncodeToString([]byte(raw))
			return map[string]string{
				"Authorization": "Basic " + encoded,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
