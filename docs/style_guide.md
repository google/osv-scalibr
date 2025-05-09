# OSV-SCALIBR style guide

OSV-SCALIBR, like most of Google's Go projects, follows the [Google Go style guide](https://google.github.io/styleguide/go).
Apart from this, we have some specific OSV-SCALIBR specific best practices:

## Code structure

### Line length

Use 80 characters per line when possible. Exceptions apply if splitting
something into several lines hurts readability.

### Short functions

Prefer short functions. If a function is getting too large, consider moving
self-contained parts of the business logic into separate private helper
functions with descriptive names, even if they're only called once.

Similarly, if the list of params to a function is getting too long, consider
moving them to an [option structure](https://google.github.io/styleguide/go/best-practices.html#option-structure).
This shortens the function definitions and makes it easier to oversee the
purpose of each param.

### Function ordering: General to specific

Define the public structs/functions/etc. in a class first, then define the
private functions.

Within private functions, define the higher-order ones first. E.g. if function
`a()` is calling `b()`, define `a` first, then `b`.

### Short inline functions

Keep inline functions short. If they're getting long, prefer moving them into a
separate named private function.

Since inline functions can capture vars from the parent function they can get
hard to oversee if they grow too large. By factoring them into separate
functions, any vars from the parent function have to be passed as parameters,
making it easier to understand how the function affects the surrounding code.

### Inline constants

If a constant is private and used only once, prefer inlining it where it's used
instead of adding a top-level const declaration.

Regexes are exempt from this since they should be initialized at startup - See
the section below for more details.

### Avoid init()

Usage of `init()` makes it hard to keep track of the control flow. Prefer
avoiding it in production code. In tests you can use `TestMain()` instead.

### Context propagation

OSV-SCALIBR library users can pass in a `context.Context` to control timeouts and
context cancellation. Make sure this top-level context is passed down to lower
functions (don't initialize a new context with `context.Background()`) and check
for context cancellation whenever something long-running is performed such as
looping ([example](https://github.com/google/osv-scalibr/blob/8b03d0859edf445152f34c420f50ffe0abf057df/extractor/filesystem/os/dpkg/dpkg.go#L183)).

## Error handling

### Avoid panics

If a plugin encounters an error the rest of OSV-SCALIBR and the callers' code
shouldn't crash. Avoid calling panics and prefer propagating errors instead.

### Init regexes at startup time

Add all regex definitions that use `MustCompile` as global vars that initialize
at startup time ([example](https://github.com/google/osv-scalibr/blob/8b03d0859edf445152f34c420f50ffe0abf057df/extractor/filesystem/os/nix/nix.go#L92)). This allows the initialization computation to be done up front and
catches any potential crashes before the scan runs.

### Propagate or log errors

In general, propagate errors upwards to the caller.

If the error is expected or not something that should make the module fail
(e.g. an Extractor encountered an invalid package.json file) there's no need to
propagate it but consider logging a warning instead.

## Testing

### Don't use `t.Parallel()`

While `t.Parallel()` allows tests to run faster, they cause test logs in our
internal systems to be mixed together for various test cases, making them harder
to read. OSV-SCALIBR unit tests also only take a couple of seconds to run so there's
not much benefit in adding `t.Parallel()` at the moment.

### Avoid assertion libraries

Generally avoid creating helper libraries that [perform test assertions](https://google.github.io/styleguide/go/decisions.html#assertion-libraries).
Instead, use helper libs to transform your data into a more easily comparable
structure and perform the comparisions/assertions in the main test function.
Example: the [extracttest](https://github.com/google/osv-scalibr/blob/8b03d0859edf445152f34c420f50ffe0abf057df/extractor/filesystem/language/dart/pubspec/pubspec_test.go#L296)
helper lib.

An exception is when the helper library is used to set up the testing
environment (e.g. create specific files). In these cases it's fine to assert
that the setup succeeded in the library function as long as the setup code is
not related to the functionality being tested ([example](https://github.com/google/osv-scalibr/blob/8b03d0859edf445152f34c420f50ffe0abf057df/extractor/filesystem/os/dpkg/dpkg_test.go#L1527)).

### Use easy to find subtest descriptions

Use only alphanumeric characters and underscores in test descriptions. Don't use
spaces. Test logs transform these descriptions by substituting the spaces which
makes the failing tests from the logs harder to find in the code ([example](/binary/cli/cli_test.go#L258;rcl=732940634)).

### Test for multi-platform support

OSV-SCALIBR runs on Linux, Windows, and Mac. When adding new code, make sure your
code is compatible with all 3 OSes or that you're adding a component that's only
meant to run on a given OS. Check that the SCALIBR Github Actions for all 3 OSes
pass.

When using OS specific helper libraries consider adding dummy implementations
for other OSes ([example](https://github.com/google/osv-scalibr/blob/main/extractor/standalone/windows/ospackages/ospackages_dummy.go)).

One common change that fails on Window is introducing file path processing code
that uses the wrong kinds of slashes (`/` vs `\`). When dealing with absolute
paths, use built-in functions such as `filepath.Join()` to handle path
operations. Virtual paths use the `fs.FS` interface which uses `/` even on
Windows.  In these cases you can sanitize your paths with `filepath.ToSlash`
([example](https://github.com/google/osv-scalibr/blob/daa1498e42aafe6a9258df854cb3bfee17b6808b/extractor/filesystem/language/python/requirements/requirements.go#L193)).

## Performance

OSV-SCALIBR is meant to also run on systems with constrained resources and new code
should thus try to keep its runtime and resource usage low. Plugins that have a
high resource consumption will be able to run in less contexts and will thus be
less useful.

### Avoid expensive operations in `FileRequired`

Extractor plugins' `FileRequired()` function can get called on every file on the
scanned filesystem. Keep the checks simple by using simple string comparison
logic. Define the checks inside `FileRequired()` instead of separate functions
as function calls can add additional runtime overhead.

Avoid doing expensive file path comparisons such as regexp matching unless
you've already pre-filtered the files and can be sure that the more expensive
operations will only run on a small subset of the files.

### Avoid reading full binaries into memory

When parsing binaries and lockfiles that can get large, avoid reading all of the
file contents into memory whenever possible. Prefer to use streaming readers.
For reading a specific section of a large file, perfer using [`ReadAt()`](https://pkg.go.dev/io#ReaderAt)
instead of slicing out the relevant sections in memory.

## Miscellaneous

### Use the Unit lib for large numbers

OSV-SCALIBR has a [unit lib](https://github.com/google/osv-scalibr/blob/main/extractor/filesystem/internal/units/units.go)
for commonly used data size units. Use the values from these lib instead code
like `"2 * 1024 * 1024"`.

### Prefer %q over %s

When formatting strings, `%q` adds escapes and quotation marks and makes it
easier to see where a string variable in the log message starts. It also makes
it easier to see empty strings in logs ([example](https://github.com/google/osv-scalibr/blob/daa1498e42aafe6a9258df854cb3bfee17b6808b/scalibr.go#L118)).

### Add docstrings to public functions and types

All public functions and type should have [doc comments](https://tip.golang.org/doc/comment).
