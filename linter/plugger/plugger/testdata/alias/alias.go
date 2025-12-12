package alias

import "testdata/basic"

func NewDefault() basic.MyPlugin {
	return basic.NewPluginA()
}

func NewDetector() basic.MyPlugin {
	return basic.NewPluginA()
}

func NewValidator() basic.MyPlugin {
	return basic.NewPluginA()
}
