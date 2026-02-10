package discordbottoken

import (
	"context"
	"regexp"

	"github.com/google/osv-scalibr/veles"
)

var tokenRegex = regexp.MustCompile(`(?m)[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}`)

type Detector struct{}

func (d Detector) Detect(ctx context.Context, input veles.Input) ([]veles.Secret, error) {
	var results []veles.Secret

	matches := tokenRegex.FindAllString(input.Data, -1)
	for _, match := range matches {
		results = append(results, &DiscordBotToken{
			SecretBase: veles.NewSecretBase(match),
		})
	}

	return results, nil
}
