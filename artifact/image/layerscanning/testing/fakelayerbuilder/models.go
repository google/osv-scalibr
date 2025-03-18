package fakelayerbuilder

type FakeTestLayers struct {
	Layers []struct {
		Files map[string][]string `yaml:"files"`
	} `yaml:"layers"`
}
