export PATH := $(PATH):$(shell go env GOPATH)/bin

scalibr:
	# CGO is required for certain dependencies such as
	# go-sqlite3 used by the RPM extractor.
	CGO_ENABLED=1 go build binary/scalibr/scalibr.go

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.5.0 run ./...

test:
	CGO_ENABLED=1 go test ./...

protos:
ifeq ($(OS),Windows_NT)
	powershell.exe -exec bypass -File .\build_protos.ps1
else
	./build_protos.sh
endif

scalibr-static:
	CGO_ENABLED=1 go build -ldflags="-extldflags=-static" binary/scalibr/scalibr.go

clean:
	rm -f scalibr
