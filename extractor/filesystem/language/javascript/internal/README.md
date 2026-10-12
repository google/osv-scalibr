# JavaScript Internal Packages

## json_line_finder.go

Provides a JSONLineFinder struct that can be used for parsing line numbers of
packages declared in JSON file formats.

It uses the `gjson` package, which is a high performance parser for JSON.

### Primer on `lineOffsets` and how they're used

Consider this JSON:

```json
{
  "foo": "bar",
  "baz": 123
}
```

This string is equivalent to: `"{\n  \"foo\": \"bar\",\n  \"baz\": 123\n}"`.

When `NewJSONLineFinder` initializes, it populates `lineOffsets` as follows:

1.  `lineOffsets[0] = 0` (Line 1: `{`)

2.  `lineOffsets[1] = 2` (Line 2: `  "foo": "bar",`, starting immediately after
    the first `\n`)

3.  `lineOffsets[2] = 18` (Line 3: `  "baz": 123`, starting immediately after
    the second `\n`)

4.  `lineOffsets[3] = 31` (Line 4: `}`)

For a given array element in `lineOffsets`:

*   The index is the line number in the file.

*   The value is the number of the byte offset.

The `gjson` library can scan JSON and return the raw byte "index" of a given
string. We can then do a binary search to find out where this byte index lands
in terms of the actual file line number.

Consider the call `LineOf("baz")`.

1.  `gjson.Get` retrieves the result and tells us `123` starts at
    `res.Index = 27`.

2.  `sort.Search` executes an $O(\log N)$ binary search over
    `lineOffsets = [0, 2, 18, 31]` to find the smallest index `i` where
    `lineOffsets[i] > 27`.

`sort.Search` evaluates `lineOffsets[3] = 31 > 27` and returns index `3`.

Because `sort.Search` returns the 0-based index of the *next* line (`31`), it
perfectly matches the **1-based** line number of the *current* line (`18`).
