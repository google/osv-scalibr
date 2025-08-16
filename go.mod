module github.com/google/osv-scalibr

go 1.23.0

require (
	github.com/google/uuid v1.4.0
	github.com/gorilla/mux v1.8.1
	github.com/prometheus/client_golang v1.23.0
	golang.org/x/time v0.5.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.65.0 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	golang.org/x/sys v0.33.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

replace github.com/docker/docker/api => github.com/moby/moby/api v1.52.0-alpha.1

replace github.com/docker/docker/client => github.com/moby/moby/client v0.1.0-alpha.0
