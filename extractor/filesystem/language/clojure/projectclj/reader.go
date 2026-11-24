// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package projectclj

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// This file holds a minimal streaming reader for the subset of Clojure syntax
// that appears in project.clj files. It only has to tell collections, symbols,
// keywords and strings apart; everything else is read and kept as an opaque
// form so that it never desynchronises the surrounding structure.

// maxNestingDepth bounds how deeply forms may nest. Collections and reader
// prefixes such as ' or ^ each count as one level. Real project.clj files
// nest a handful of levels; the bound keeps a hostile file from exhausting
// the stack.
const maxNestingDepth = 256

type formKind int

const (
	kindOther formKind = iota
	kindList
	kindVector
	kindMap
	kindSet
	kindSymbol
	kindKeyword
	kindString
	kindUnquote // ~form or ~@form
)

type form struct {
	kind     formKind
	text     string
	children []*form
	line     int
}

// closeError is returned by read when it meets a closing delimiter instead of
// a form. The collection reader uses it to find the end of its elements.
type closeError struct{ delim rune }

func (e closeError) Error() string {
	return fmt.Sprintf("unexpected closing delimiter %q", e.delim)
}

type reader struct {
	in   *bufio.Reader
	line int
}

func newReader(in io.Reader) *reader {
	return &reader{in: bufio.NewReader(in), line: 1}
}

func (r *reader) next() (rune, error) {
	c, _, err := r.in.ReadRune()
	if err == nil && c == '\n' {
		r.line++
	}
	return c, err
}

// unread puts back c, which must be the rune the last call to next returned.
func (r *reader) unread(c rune) {
	_ = r.in.UnreadRune()
	if c == '\n' {
		r.line--
	}
}

func isWhitespace(c rune) bool { return unicode.IsSpace(c) || c == ',' }

// isDelimiter reports whether c ends a symbol, keyword or number: whitespace
// and the characters the Clojure reader calls terminating macro characters.
// read handles every one of them before it falls back to readToken, so a
// token is never empty there.
func isDelimiter(c rune) bool {
	return isWhitespace(c) || strings.ContainsRune("()[]{}\";@^`~\\", c)
}

// skipLine consumes the rest of the current line.
func (r *reader) skipLine() error {
	for {
		c, err := r.next()
		if err != nil {
			return err
		}
		if c == '\n' {
			return nil
		}
	}
}

// skipIgnored consumes everything the Clojure reader produces no form for:
// whitespace, line comments starting with ; or #! and forms discarded with
// #_. It is a loop, so any number of them in a row costs no nesting.
func (r *reader) skipIgnored(depth int) error {
	for {
		if p, _ := r.in.Peek(2); len(p) == 2 && p[0] == '#' && (p[1] == '!' || p[1] == '_') {
			discard := p[1] == '_'
			_, _ = r.in.Discard(2)
			if discard {
				if _, err := r.readOperand(depth); err != nil {
					return err
				}
			} else if err := r.skipLine(); err != nil {
				return err
			}
			continue
		}

		c, err := r.next()
		if err != nil {
			return err
		}
		switch {
		case c == ';':
			if err := r.skipLine(); err != nil {
				return err
			}
		case !isWhitespace(c):
			r.unread(c)
			return nil
		}
	}
}

// read returns the next form. It returns io.EOF when the input ends between
// forms and a closeError when it meets a closing delimiter.
func (r *reader) read(depth int) (*form, error) {
	if depth > maxNestingDepth {
		return nil, fmt.Errorf("line %d: forms nested deeper than %d", r.line, maxNestingDepth)
	}
	if err := r.skipIgnored(depth); err != nil {
		return nil, err
	}
	line := r.line
	c, err := r.next()
	if err != nil {
		return nil, err
	}

	switch c {
	case '(':
		return r.readColl(kindList, ')', line, depth)
	case '[':
		return r.readColl(kindVector, ']', line, depth)
	case '{':
		return r.readColl(kindMap, '}', line, depth)
	case ')', ']', '}':
		return nil, closeError{delim: c}
	case '"':
		s, err := r.readString()
		if err != nil {
			return nil, err
		}
		return &form{kind: kindString, text: s, line: line}, nil
	case '\'', '`', '@':
		// Quote, syntax quote and deref do not change what is being declared.
		return r.readOperand(depth)
	case '~':
		next, err := r.next()
		if err != nil {
			return nil, unexpectedEOF(err)
		}
		if next != '@' {
			r.unread(next)
		}
		inner, err := r.readOperand(depth)
		if err != nil {
			return nil, err
		}
		return &form{kind: kindUnquote, children: []*form{inner}, line: line}, nil
	case '^':
		return r.readAnnotated(depth)
	case '\\':
		// Character literal: \a, \newline, \] ...
		if _, err := r.next(); err != nil {
			return nil, unexpectedEOF(err)
		}
		if _, err := r.readToken(); err != nil {
			return nil, err
		}
		return &form{kind: kindOther, line: line}, nil
	case '#':
		return r.readDispatch(line, depth)
	}

	r.unread(c)
	tok, err := r.readToken()
	if err != nil {
		return nil, err
	}
	switch {
	case strings.HasPrefix(tok, ":"):
		return &form{kind: kindKeyword, text: tok, line: line}, nil
	case isNumber(tok):
		return &form{kind: kindOther, text: tok, line: line}, nil
	default:
		return &form{kind: kindSymbol, text: tok, line: line}, nil
	}
}

// readOperand reads the form a prefix such as ' or ^ applies to, one nesting
// level below the prefix. Running out of input or meeting a closing delimiter
// there is malformed input.
func (r *reader) readOperand(depth int) (*form, error) {
	f, err := r.read(depth + 1)
	if ce := (closeError{}); errors.As(err, &ce) {
		return nil, fmt.Errorf("line %d: missing form before %q", r.line, ce.delim)
	}
	if err != nil {
		return nil, unexpectedEOF(err)
	}
	return f, nil
}

// readAnnotated reads what follows a metadata prefix, ^ or the older #^, as
// in ^:replace [...]: the metadata is read and dropped, the form it annotates
// is returned.
func (r *reader) readAnnotated(depth int) (*form, error) {
	if _, err := r.readOperand(depth); err != nil {
		return nil, err
	}
	return r.readOperand(depth)
}

func (r *reader) readColl(kind formKind, closing rune, line, depth int) (*form, error) {
	f := &form{kind: kind, line: line}
	for {
		el, err := r.read(depth + 1)
		if ce := (closeError{}); errors.As(err, &ce) {
			if ce.delim != closing {
				return nil, fmt.Errorf("line %d: expected %q, found %q", r.line, closing, ce.delim)
			}
			return f, nil
		}
		if err != nil {
			return nil, unexpectedEOF(err)
		}
		f.children = append(f.children, el)
	}
}

// readDispatch reads what follows a # other than the #! and #_ that
// skipIgnored consumes.
func (r *reader) readDispatch(line, depth int) (*form, error) {
	c, err := r.next()
	if err != nil {
		return nil, unexpectedEOF(err)
	}
	switch c {
	case '{':
		return r.readColl(kindSet, '}', line, depth)
	case '^':
		return r.readAnnotated(depth)
	case '"':
		// Regex literal.
		if _, err := r.readString(); err != nil {
			return nil, err
		}
		return &form{kind: kindOther, line: line}, nil
	case '(':
		// Anonymous function: read it but never treat it as data.
		f, err := r.readColl(kindList, ')', line, depth)
		if err != nil {
			return nil, err
		}
		f.kind = kindOther
		return f, nil
	case '?':
		// Reader conditional #?(...) or #?@(...): kept opaque.
		next, err := r.next()
		if err != nil {
			return nil, unexpectedEOF(err)
		}
		if next != '@' {
			r.unread(next)
		}
		f, err := r.readOperand(depth)
		if err != nil {
			return nil, err
		}
		return &form{kind: kindOther, children: f.children, line: line}, nil
	case '\'':
		// Var quote #'sym.
		return r.readOperand(depth)
	case '#':
		// Symbolic value such as ##Inf.
		if _, err := r.readToken(); err != nil {
			return nil, err
		}
		return &form{kind: kindOther, line: line}, nil
	case ':':
		// Namespaced map #:ns{...}: drop the prefix, keep the map.
		if _, err := r.readToken(); err != nil {
			return nil, err
		}
		return r.readOperand(depth)
	}
	// Tagged literal such as #inst "...": the tag, then the tagged form.
	r.unread(c)
	if _, err := r.readToken(); err != nil {
		return nil, err
	}
	if _, err := r.readOperand(depth); err != nil {
		return nil, err
	}
	return &form{kind: kindOther, line: line}, nil
}

func (r *reader) readString() (string, error) {
	var b strings.Builder
	for {
		c, err := r.next()
		if err != nil {
			return "", unexpectedEOF(err)
		}
		switch c {
		case '"':
			return b.String(), nil
		case '\\':
			esc, err := r.next()
			if err != nil {
				return "", unexpectedEOF(err)
			}
			switch esc {
			case 'n':
				b.WriteRune('\n')
			case 't':
				b.WriteRune('\t')
			default:
				b.WriteRune(esc)
			}
		default:
			b.WriteRune(c)
		}
	}
}

// readToken reads a symbol, keyword or number up to the next delimiter.
func (r *reader) readToken() (string, error) {
	var b strings.Builder
	for {
		c, err := r.next()
		if errors.Is(err, io.EOF) {
			return b.String(), nil
		}
		if err != nil {
			return "", err
		}
		if isDelimiter(c) {
			r.unread(c)
			return b.String(), nil
		}
		b.WriteRune(c)
	}
}

func isNumber(tok string) bool {
	t := strings.TrimLeft(tok, "+-")
	return t != "" && unicode.IsDigit(rune(t[0]))
}

func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
