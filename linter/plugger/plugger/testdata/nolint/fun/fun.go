package fun

import "testdata/basic"

func NewPlugin() basic.MyPlugin {
	return &basic.PluginA{}
}

//nolint:plugger // This function is meant to be used only in testing as it returns the same plugin as fun.NewPlugin
func NewPluginAlias(something string) basic.MyPlugin {
	return &basic.PluginA{}
}
