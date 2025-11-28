package external

import "testdata/basic"

func NewPluginExternal() any {
	return basic.PluginA{}
}

func NewPluginExternalWithoutConcrete() basic.MyPlugin {
	return basic.NewPluginA()
}
