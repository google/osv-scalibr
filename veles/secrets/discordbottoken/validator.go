package discordbottoken

import (
	"errors"
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const discordAPIEndpoint = "https://discord.com/api/v10/users/@me"

// NewValidator creates a validator for Discord bot tokens.
//
// It performs a GET request to /users/@me with
// Authorization: Bot <token>
//
// Valid tokens return 200 OK.
// Invalid tokens return 401 Unauthorized or 403 Forbidden.
func NewValidator() *sv.Validator[DiscordBotToken] {
	return &sv.Validator[DiscordBotToken]{
		EndpointFunc: func(t DiscordBotToken) (string, error) {
			if t.Raw() == "" {
				return "", errors.New("discord bot token is empty")
			}
			return discordAPIEndpoint, nil
		},
		HTTPMethod: http.MethodGet,
		HeadersFunc: func(t DiscordBotToken) http.Header {
			h := http.Header{}
			h.Set("Authorization", "Bot "+t.Raw())
			return h
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized, http.StatusForbidden},
	}
}
