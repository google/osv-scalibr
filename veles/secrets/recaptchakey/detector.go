package recaptchakey

import (
	"bufio"
	"bytes"
	"regexp"
	"slices"

	"github.com/google/osv-scalibr/veles"
)

var (
	// inlinePattern matches an inline assignment of a captcha secret key and captures its value (works for .env and .json)
	inlinePattern = regexp.MustCompile(`(?i)captcha[._-]?(?:secret|private)[a-zA-Z_]*\\*"?\s*[:=]\s*['"]?(6[A-Za-z0-9_-]{39})\b`)
	// jsonBlockPattern matches a json object with the key ending in captcha and then extract the value of a secret key
	jsonBlockPattern = regexp.MustCompile(`captcha\\*"\s?:\s?\{[^\{]*?(?:private|secret)[a-zA-Z_]*\\*['"]?\s?:\s?\\*['"]?(6[A-Za-z0-9_-]{39})\b`)
	// yamlPattern matches a reCAPTCHA secret key inside a yaml file, it's meant to be used after a reCAPTCHA yaml block has been identified
	yamlPattern = regexp.MustCompile(`(?i)(?:private|secret)[a-zA-Z_]*\s*:\s*['"]?(6[A-Za-z0-9_-]{39}\b)`)
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

type block struct {
	active bool
	indent int
}

// findInsideYamlBlock searches for inlineYamlPattern inside `captcha:` yaml blocks
func findInsideYamlBlock(data []byte) [][]int {
	var results [][]int
	sc := bufio.NewScanner(bytes.NewReader(data))

	var b block
	offset := 0

	for sc.Scan() {
		line := sc.Bytes()

		// Start of a captcha block
		if bytes.Contains(line, []byte("captcha:")) {
			b.active = true
			b.indent = countIndent(line)
			offset += len(line) + 1
			continue
		}

		// If not in block, just advance offset
		if !b.active {
			offset += len(line) + 1
			continue
		}

		// End of captcha block if indentation drops
		if countIndent(line) <= b.indent {
			b.active = false
			offset += len(line) + 1
			continue
		}

		// Look for private/secret keys only inside block
		matches := yamlPattern.FindAllSubmatchIndex(line, -1)
		for _, m := range matches {
			if len(m) < 4 {
				continue
			}
			// Adjust to file offset
			results = append(results, []int{
				offset + m[0], offset + m[1], // full match
				offset + m[2], offset + m[3], // first capture group
			})
		}

		offset += len(line) + 1
	}

	return results
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
