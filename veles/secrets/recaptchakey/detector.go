package recaptchakey

import (
	"bufio"
	"bytes"
	"regexp"
	"slices"

	"github.com/google/osv-scalibr/veles"
)

var (
	// inlinePattern matches an inline assignment of a captcha secret key and captures its value (works for .env .json and .yaml)
	inlinePattern = regexp.MustCompile(`(?i)captcha[._-]?(?:secret|private)[a-zA-Z_]*\\*"?\s*[:=]\s*['"]?(6[A-Za-z0-9_-]{39})\b`)
	// jsonBlockPattern matches a json object with the key ending in captcha and then extract the value of a secret key
	jsonBlockPattern = regexp.MustCompile(`(?i)captcha\\*"\s?:\s?\{[^\{]*?(?:private|secret)[a-zA-Z_]*\\*['"]?\s?:\s?\\*['"]?(6[A-Za-z0-9_-]{39})\b`)
	// yamlBlockPattern roughly searches for a yaml block with a secret key near it (leaving space before to check for indentation)
	yamlBlockPattern = regexp.MustCompile(`(?i)\s*([a-zA-Z_]*captcha:[\r\n]+)[\s\S]{0,300}(?:private|secret)[a-zA-Z_]*\s*:\s*['"]?(6[A-Za-z0-9_-]{39}\b)`)
)

const (
	maxSecretLen  = 40
	maxContextLen = 500
	maxLen        = maxSecretLen + maxContextLen
)

type detector struct{}

// NewDetector returns a reCAPTCHA secret keys detector
func NewDetector() veles.Detector { return &detector{} }

// Detect matches reCAPTCHA keys in config files,
func (d *detector) Detect(data []byte) ([]veles.Secret, []int) {
	matches := slices.Concat(
		inlinePattern.FindAllSubmatchIndex(data, -1),
		jsonBlockPattern.FindAllSubmatchIndex(data, -1),
		findInsideYamlBlock(data),
	)

	var secrets []veles.Secret
	var positions []int

	// Process regex-based matches
	for _, m := range matches {
		start := m[len(m)-2]
		end := m[len(m)-1]
		if start == -1 || end == -1 {
			continue
		}
		secrets = append(secrets, Key{Secret: string(data[start:end])})
		positions = append(positions, start)
	}
	return secrets, positions
}

// MaxSecretLen returns the length a secret can have
func (d *detector) MaxSecretLen() uint32 { return maxLen }

// findInsideYamlBlock searches for inlineYamlPattern inside `captcha:` yaml blocks
func findInsideYamlBlock(data []byte) [][]int {
	matches := yamlBlockPattern.FindAllSubmatchIndex(data, -1)
	matches = slices.DeleteFunc(matches, func(m []int) bool {
		blockKeyIndent := m[2] - m[0] // distance between the full match and the (captcha) capture group
		block_start := m[3]           // end of key group
		end := m[1]                   // end of full match

		r := bufio.NewScanner(bytes.NewReader(data[block_start+1 : end]))
		for r.Scan() {
			line := r.Bytes()
			trimmed := bytes.TrimSpace(line)
			// skip empty lines and comments
			if len(trimmed) == 0 || trimmed[0] == '#' {
				continue
			}
			// if the indent is less then the block's the key is in another block
			if countIndent(line) < blockKeyIndent {
				return true
			}
		}
		return false
	})
	return matches
}

// countIndent calculates the number of leading spaces or tabs in a byte slice.
func countIndent(s []byte) int {
	for i, r := range s {
		if r != ' ' && r != '\t' {
			return i
		}
	}
	return len(s)
}
