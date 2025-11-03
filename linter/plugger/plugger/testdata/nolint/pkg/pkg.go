//nolint:plugger // test
package pkg

import "testdata/basic"

func NewPluginNeverCalledButNotLinted() basic.MyPlugin { return basic.NewPluginA() }
