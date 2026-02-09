package discordbottoken

import (
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/veles/secrets"
	"github.com/google/osv-scalibr/veles/secrets/detectors"
)

var (
	// Bot token regex (non-MFA)
	botTokenRegex = regexp.MustCompile(`(?i)[MN][A-Za-z\d_-]{23}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27}`)

	// MFA token regex (rare but valid)
	mfaTokenRegex = regexp.MustCompile(`(?i)mfa\.[A-Za-z\d_-]{20,}`)

	// Context keywords to reduce false positives
	contextKeywords = []string{
		"discord",
		"bot",
		"token",
		"client",
		"authorization",
	}
)

// Detector detects Discord bot tokens.
type Detector struct{}

func (d Detector) Detect(input detectors.Input) ([]secrets.Secret, error) {
	var results []secrets.Secret

	contentLower := strings.ToLower(input.Content)

	// Context gate (cheap + effective)
	if !containsAny(contentLower, contextKeywords) {
		return nil, nil
	}

	// Check both token types
	for _, re := range []*regexp.Regexp{botTokenRegex, mfaTokenRegex} {
		matches := re.FindAllStringIndex(input.Content, -1)
		for _, match := range matches {
			secret := &DiscordBotToken{}
      secret.SecretBase = secrets.NewSecretBase(
	    input.Content[match[0]:match[1]],
	    input.Location,
)

			

			results = append(results, secret)
		}
	}

	return results, nil
}

// Helper: keyword proximity check
func containsAny(content string, keywords []string) bool {
	for _, k := range keywords {
		if strings.Contains(content, k) {
			return true
		}
	}
	return false
}
