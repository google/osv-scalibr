package discard

import (
	"bufio"
	"slices"
)

// LongLines returns a bufio.SplitFunc that discards lines exceeding maxLineSize.
func LongLines(maxLineSize int) bufio.SplitFunc {
	isSkipping := false

	return func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if isSkipping {
			if crIdx := slices.Index(data, '\n'); crIdx != -1 {
				// if newline is found stop skipping
				isSkipping = false
				return crIdx + 1, nil, nil
			}
			// keep skipping
			return len(data), nil, nil
		}

		advance, token, err = bufio.ScanLines(data, atEOF)

		// If buffer is full and no newline was found, trigger skip mode
		if advance == 0 && token == nil && err == nil && len(data) >= maxLineSize {
			isSkipping = true
			return len(data), nil, nil
		}

		return advance, token, err
	}
}
