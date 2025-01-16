package client

import (
	"deps.dev/util/resolve"
)

type DependencyClient interface {
	resolve.Client
	// AddRegistries adds the specified registries to fetch data.
	AddRegistries(registries []Registry) error
}

type Registry interface{}
