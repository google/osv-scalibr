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

### No lint rules

exclude a function

```go
// This function is called
func NewPlugin() basic.MyPlugin {
	return &basic.PluginA{}
}

// This is treated as alias automatically
func NewPluginAlias(something string) basic.MyPlugin {
	return &basic.PluginA{}
}

// NewForTest: since this function is intended to be used in tests only,
// must be excluded from the lint
//
//nolint:plugger // This function is meant to be used only in testing and returns the same plugin as fun.NewPlugin
func NewForTest(something string) basic.MyPlugin {
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
