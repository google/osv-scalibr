package simplevalidate

type Validator[S any] struct {
	Endpoint  string
	Endpoints []string
}
