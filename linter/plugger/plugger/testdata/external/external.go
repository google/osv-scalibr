package external

import "testdata/basic"

func NewPluginExternal() basic.MyPlugin {
	return &basic.PluginA{}
}

func NewPluginExternalWithoutConcrete() basic.MyPlugin {
	return basic.NewPluginA()
}
