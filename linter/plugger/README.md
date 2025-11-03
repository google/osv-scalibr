# Plugger

Searches for not registered plugins: a plugin is a struct that implements a
given interface.

## Usage

```sh
~ plugger -h
Usage of plugger:
  -interface value
    list of interfaces (repeatable), ex: '-interface github.com/pkg.Interface'
```

### Exclude plugins

Also excluding a plugin directly is possible, just add a `//nolint:plugger`
directive

```go
// Extractor extracts python packages from requirements.txt files.
//
//nolint:plugger // This plugin will be removed shortly
type Extractor struct {
  resolve.Client
  BaseExtractor *requirements.Extractor
}
```

exclude a function

```go
func NewPlugin() basic.MyPlugin {
	return &basic.PluginA{}
}

//nolint:plugger // This function is meant to be used only in testing and returns the same plugin as fun.NewPlugin
func NewPluginAlias(something string) basic.MyPlugin {
	return &basic.PluginA{}
}
```

or directly exclude a pkg

```go
// Package fakeplugin contains a fake plugin to be used in testing
//
//nolint:plugger // This pkg contains only mocks
package fakeplugin
```
