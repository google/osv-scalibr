package requirements

import (
	"bufio"
	"strings"
	"testing"
)

// A requirements.txt of backslash continued lines used to recurse once per line,
// and a Go stack overflow cannot be recovered from.
func TestReadLineDeepContinuation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping deep continuation test in short mode")
	}

	const lines = 6_000_000

	var sb strings.Builder
	sb.Grow(lines * 3)
	for i := 0; i < lines; i++ {
		sb.WriteString("a\\\n")
	}
	sb.WriteString("b\n")

	s := bufio.NewScanner(strings.NewReader(sb.String()))
	s.Scan()
	got, _ := readLine(s, 1, &strings.Builder{})

	if want := lines + 1; len(got) != want {
		t.Errorf("joined %d characters, want %d", len(got), want)
	}
}
