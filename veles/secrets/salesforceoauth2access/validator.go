package salesforceoauth2access

import (
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// NewValidator creates a new Salesforce OAuth Token Validator.
//
// It performs a GET request to the Salesforce token endpoint.
// If the request returns HTTP 200, the credentials are valid.
// If 401 Unauthorized, they are invalid.
func NewValidator() *sv.Validator[Token] {
	return &sv.Validator[Token]{
		Endpoint:   "https://login.salesforce.com/services/oauth2/userinfo",
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(token Token) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + token.Token,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized},
	}
}
