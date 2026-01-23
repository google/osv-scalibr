package discordbottoken

import (
	"context"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/veles/secrets"
)

const discordAPIURL = "https://discord.com/api/v10/users/@me"

type Validator struct{}

func (v Validator) Validate(ctx context.Context, secret secrets.Secret) (secrets.ValidationResult, error) {
	token, ok := secret.(*DiscordBotToken)
	if !ok {
		return secrets.ValidationResult{}, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discordAPIURL, nil)
	if err != nil {
		return secrets.ValidationResult{}, err
	}

	req.Header.Set("Authorization", "Bot "+token.Raw())

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return secrets.ValidationResult{}, nil
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return secrets.ValidationResult{
			Confirmed: true,
		}, nil

	case http.StatusUnauthorized, http.StatusForbidden:
		return secrets.ValidationResult{
			Confirmed: false,
		}, nil

	default:
		return secrets.ValidationResult{}, nil
	}
}
