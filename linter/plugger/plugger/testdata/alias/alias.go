package alias

import "testdata/basic"

func NewAlias() basic.MyPlugin {
	return basic.NewPluginA()
}

func NewDefault() basic.MyPlugin {
	return basic.NewPluginA()
}

func NewDetector() basic.MyPlugin {
	return basic.NewPluginA()
}

func NewValidator() basic.MyPlugin {
	return basic.NewPluginA()
}
