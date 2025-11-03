//nolint:plugger // test
package pkgnolint

import "testdata/basic"

func NewPluginNeverCalledButNotLinted() basic.MyPlugin { return basic.NewPluginA() }
