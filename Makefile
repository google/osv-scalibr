export PATH := $(PATH):$(shell go env GOPATH)/bin

scalibr: protos
	go build binary/scalibr.go

test: protos
	go test ./...

protos:
	./build_protos.sh

clean:
	rm -rf binary/proto/*_go_proto
	rm -f scalibr
