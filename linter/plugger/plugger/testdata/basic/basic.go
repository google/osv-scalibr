package basic

type MyPlugin interface {
	Run()
}

type NotAPlugin interface {
	SomethingElse()
}

type PluginA struct{}

func (p *PluginA) Run() {}

type PluginB struct{}

func (p *PluginB) Run() {}

func NewPluginA() MyPlugin { return &PluginA{} }
func NewPluginB() MyPlugin { return &PluginB{} }
