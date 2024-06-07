export PATH := $(PATH):$(shell go env GOPATH)/bin

scalibr: protos
	# CGO is required for certain dependencies such as
	# go-sqlite3 used by the RPM extractor.
	CGO_ENABLED=1 go build binary/scalibr.go

test: protos
	CGO_ENABLED=1 go test ./...

protos:
ifeq ($(OS),Windows_NT)
	powershell.exe -exec bypass -File .\build_protos.ps1
else
	./build_protos.sh
endif

scalibr-static: protos
	CGO_ENABLED=1 go build -ldflags="-extldflags=-static" binary/scalibr.go

clean:
	rm -f scalibr
