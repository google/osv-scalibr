package token

// GithubToken is the interface for any Github token
type GithubToken interface {
	GetToken() string
}
