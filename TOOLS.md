# Development Tools for OSV‑SCALIBR

This document lists all the tools you need to build, test, and contribute to the **OSV‑SCALIBR** project.

## Core Language & Build

| Tool | Version | Install / Setup |
|------|---------|----------------|
| **Go** | 1.22+ (latest stable) | - **Linux/macOS**: `brew install go` or download from https://golang.org/dl/ <br> - **Windows**: Download MSI installer from the Go website. |
| **Make** | any (GNU Make) | - **Linux/macOS**: pre‑installed on most distros. <br> - **Windows**: Install via [Chocolatey](`choco install make`) or use the `make` binary from GNU. |
| **Git** | 2.30+ | Standard Git installation. |
| **Docker** (optional) | latest | Required for container‑related tests. <br> - **Linux/macOS**: `brew install --cask docker` <br> - **Windows**: Install Docker Desktop. |
| **Protobuf Compiler (`protoc`)** | 3.21+ | - **Linux/macOS**: `brew install protobuf` <br> - **Windows**: Download `protoc-*.zip` from https://github.com/protocolbuffers/protobuf/releases and add `bin` to `PATH`. |
| **`protoc-gen-go`** | latest | `go install google.golang.org/protobuf/cmd/protoc-gen-go@latest` |
| **`protoc-gen-go-grpc`** (if needed) | latest | `go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest` |
| **`golangci-lint`** | latest | `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest` |
| **`go-licenses`** (optional) | latest | `go install github.com/google/go-licenses@latest` |
| **`go-licenses`** (optional) | latest | `go install github.com/google/go-licenses@latest` |
| **`go vet`** | built‑in with Go | Used for static analysis. |
| **`go test`** | built‑in with Go | Runs unit tests. |
| **`go mod`** | built‑in with Go | Dependency management. |
| **`git`** | any | For cloning and PR workflow. |
| **`clang-format`** (optional) | any | For formatting C/C++ files if needed. |
| **`npm`** (optional) | any | For any JavaScript tooling (e.g., linting docs). |

## Optional Tools for Development Convenience

| Tool | Purpose |
|------|--------|
| **`pre-commit`** | Run linting & formatting before commits. |
| **`goreleaser`** | Build and release binaries. |
| **`golangci-lint`** | Linting (already listed). |
| **`mockgen`** | Generate mocks for testing. |
| **`go-acc`** | Coverage reporting. |
| **`golangci-lint`** | Linting (already listed). |
| **`gocov`** | Coverage analysis. |
| **`gocritic`** | Additional static analysis. |
| **`gosec`** | Security‑focused linter (enable after fixing issues). |
| **`golangci-lint`** | Linter (already listed). |

## Setup Steps (Linux/macOS)

```bash
# Install Go
brew install go

# Install protobuf compiler and Go plugins
brew install protobuf
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Clone the repository
git clone https://github.com/google/osv-scalibr.git
cd osv-scalibr

# Install Go module dependencies
go mod tidy

# Run tests
make test

# Run linting
make lint
```

## Setup Steps (Windows)

```powershell
# Install Go (download installer)
# Install protoc (download zip, add to PATH)

# Install Go tools
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Clone repo
git clone https://github.com/google/osv-scalibr.git
cd osv-scalibr

# Install dependencies
go mod tidy

# Run tests
go test ./...

# Lint
golangci-lint run
```

## Additional Notes

* **Contributor License Agreement (CLA)** – Sign the CLA at https://cla.developers.google.com/ before submitting any PR.
* **Code style** – Follow the OSV‑SCALIBR style guide (`docs/style_guide.md`).
* **Testing** – Run `make test` or `go test ./...` on all platforms (Linux, macOS, Windows) to ensure cross‑platform compatibility.
* **Linting** – After fixing any lint errors, enable the disabled linters in `.golangci.yaml` (e.g., `gosec`, `exhaustive`, `nilnesserr`).

Feel free to add any additional tools you need for your specific contribution area (e.g., new extractor, detector, or Windows‑specific code). Happy hacking!
