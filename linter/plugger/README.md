# Plugger

Searches for not registered plugins: a plugin is a struct that implements a given interface.

## Usage

```sh
~ plugger -h
Usage of plugger /Users/just-hms/Library/Caches/go-build/06/06e00c874d5c5bb1e000de272e366cc65ebb32de196cc669944035eba56dfbc5-d/main:
  -exclude-pkg string
    	regex pattern for pkg to exclude, ex: 'github\.com/package/testing/.*' (default "a^")
  -interface string
    	regex pattern for plugin interfaces, ex: 'github\.com/package.MyInterface|.*\.OtherInterface'
```

### Exclude plugins

Also excluding a plugin directly is possible, just add a `//nolint:plugger` directive

```go
// Extractor extracts python packages from requirements.txt files.
//
//nolint:plugger: This plugin will be removed shortly
type Extractor struct {
  resolve.Client
  BaseExtractor *requirements.Extractor // The base extractor that we use to extract direct dependencies.
}
```
