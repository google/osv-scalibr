package recaptchakey

import (
	"bufio"
	"bytes"
	"regexp"
	"slices"

	"github.com/google/osv-scalibr/veles"
)

var (
	inlinePattern     = regexp.MustCompile(`(?i)captcha[._-]?(?:secret|private)[a-zA-Z_]*"?\s*[:=]\s*['"]?(6[A-Za-z0-9_-]{39})\b`)
	jsonPattern       = regexp.MustCompile(`captcha"\s?:\s?\{[^\{]*?(?:private|secret)[a-zA-Z_]*['"]?\s?:\s?['"]?(6[A-Za-z0-9_-]{39})\b`)
	inlineYamlPattern = regexp.MustCompile(`(?i)(?:private|secret)[a-zA-Z_]*\s*:\s*['"]?(6[A-Za-z0-9_-]{39}\b)`)
)

const (
	maxSecretLen = 60
	maxLen       = maxSecretLen + 150
)

type Detector struct{}

func NewDetector() veles.Detector { return &Detector{} }

func (d *Detector) Detect(data []byte) ([]veles.Secret, []int) {
	matches := slices.Concat(
		inlinePattern.FindAllSubmatchIndex(data, -1),
		jsonPattern.FindAllSubmatchIndex(data, -1),
		findYaml(data),
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

func (d *Detector) MaxSecretLen() uint32 { return maxLen }

type block struct {
	active bool
	indent int
}

// findYaml searches for inlineYamlPattern inside `captcha:` yaml blocks
func findYaml(data []byte) [][]int {
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
		matches := inlineYamlPattern.FindAllSubmatchIndex(line, -1)
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

func countIndent(s []byte) int {
	for i, r := range s {
		if r != ' ' && r != '\t' {
			return i
		}
	}
	return len(s)
}
