package discard_test

import (
	"bufio"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/common/io/discard"
)

func TestLongLines(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		maxLineSize int
		exp         []string
	}{
		{
			name:        "all_short_lines_are_kept",
			input:       "foo\nbar\nbaz\n",
			maxLineSize: 10,
			exp:         []string{"foo", "bar", "baz"},
		},
		{
			name:        "discard_single_long_line",
			input:       "ok\nthislineistoolong\nok_again\n",
			maxLineSize: 10,
			exp:         []string{"ok", "ok_again"},
		},
		{
			name:        "discard_multiple_long_lines",
			input:       "a\nloooong\nb\nevenlooonger\nc\n",
			maxLineSize: 5,
			exp:         []string{"a", "b", "c"},
		},
		{
			name:        "long_line_at_EOF",
			input:       "keep\ndiscarded_at_eof",
			maxLineSize: 6,
			exp:         []string{"keep"},
		},
		{
			name:        "exact_size_limit_boundary",
			input:       "12\n1234\n12345\n123\n",
			maxLineSize: 5,
			exp:         []string{"12", "1234", "123"},
		},
		{
			name:        "very_long_line_spanning_multiple_buffer_sizes",
			input:       "a\n" + strings.Repeat("x", 20) + "\nb\n",
			maxLineSize: 5,
			exp:         []string{"a", "b"},
		},
		{
			name:        "empty_lines_are_kept",
			input:       "\n\na\n\n",
			maxLineSize: 5,
			exp:         []string{"", "", "a", ""},
		},
		{
			name:        "empty_input",
			input:       "",
			maxLineSize: 5,
			exp:         nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := bufio.NewScanner(strings.NewReader(tt.input))

			// modify bufio.Scanner maxSize to keep the input size reasonable
			buf := make([]byte, tt.maxLineSize)
			scanner.Buffer(buf, tt.maxLineSize)

			scanner.Split(discard.LongLines(tt.maxLineSize))

			var got []string
			for scanner.Scan() {
				got = append(got, scanner.Text())
			}

			if err := scanner.Err(); err != nil {
				t.Fatalf("unexpected scanner error: %v", err)
			}

			if diff := cmp.Diff(tt.exp, got); diff != "" {
				t.Errorf("LongLines() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
