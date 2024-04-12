export PATH := $(PATH):$(shell go env GOPATH)/bin

scalibr: protos
	CGO_ENABLED=1 go build binary/scalibr.go

test: protos
	CGO_ENABLED=1 go test ./...

protos:
	./build_protos.sh

scalibr-static: protos
	CGO_ENABLED=1 go build -ldflags="-extldflags=-static" binary/scalibr.go

clean:
	rm -rf binary/proto/*_go_proto
	rm -f scalibr
