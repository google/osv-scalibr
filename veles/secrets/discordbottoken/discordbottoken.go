package discordbottoken

import "github.com/google/osv-scalibr/veles/secrets"

const (
	// Type is the unique secret type identifier
	Type secrets.Type = "discord_bot_token"
)

// DiscordBotToken represents a detected Discord bot token.
type DiscordBotToken struct {
	secrets.SecretBase
}

// Type returns the secret type.
func (s *DiscordBotToken) Type() secrets.Type {
	return Type
}
