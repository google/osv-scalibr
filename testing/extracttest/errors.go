package extracttest

import (
	"fmt"
	"strings"
)

// ContainsErrStr is an error that matches other errors that contains
// `str` in their error string.
type ContainsErrStr struct {
	Str string
}

// Error returns the error string
func (e ContainsErrStr) Error() string { return fmt.Sprintf("error contains: '%s'", e.Str) }

// Is checks whether the input error contains the string in ContainsErrStr
func (e ContainsErrStr) Is(err error) bool {
	return strings.Contains(err.Error(), e.Str)
}
