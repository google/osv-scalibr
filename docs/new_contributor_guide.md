# New Contributor Guide

Welcome to OSV-SCALIBR! This guide will help you get started contributing to the project.

## 🚀 Quick Start

### Prerequisites

1. **Go 1.24+** - [Install Go](https://golang.org/doc/install)
2. **Git** - For version control
3. **Protocol Buffers** (optional) - Only needed if modifying `.proto` files
   - `protoc` - [Install protoc](https://grpc.io/docs/protoc-installation/)
   - `protoc-gen-go` - Run `go install google.golang.org/protobuf/cmd/protoc-gen-go`

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/google/osv-scalibr.git
cd osv-scalibr

# Build the project
make

# Run tests
make test

# Run linting
make lint
```

## 🎯 Contribution Areas

### 1. 🟢 Beginner-Friendly (Good First Issues)

#### **Documentation Improvements**
- Fix typos and improve clarity
- Add code examples
- Update outdated information
- Translate documentation

#### **Test Coverage**
- Add unit tests for existing functions
- Add integration tests
- Add cross-platform test scenarios

#### **Small Bug Fixes**
- Fix linting violations
- Improve error messages
- Handle edge cases

### 2. 🟡 Intermediate (Some Experience Required)

#### **New Ecosystem Extractors**
Add support for new package managers or file formats:

**Missing Ecosystems:**
- Kotlin (Gradle Kotlin files)
- Scala (sbt files)
- Clojure (deps.edn, Leiningen)
- Zig (build.zig)
- Nim (*.nimble)
- Crystal (shard.yml)

**Implementation Steps:**
1. Create extractor in `extractor/filesystem/language/{ecosystem}/`
2. Follow existing patterns (see Python/Java extractors)
3. Add comprehensive tests
4. Update documentation

#### **Cross-Platform Improvements**
- Fix Windows path handling issues
- Add macOS-specific extractors
- Improve container support

#### **Performance Optimizations**
- Optimize file scanning
- Add parallel processing
- Improve memory usage

### 3. 🔴 Advanced (Significant Experience Required)

#### **Windows Container Support**
- Implement Windows container scanning
- Add Windows-specific layer analysis
- Handle Windows registry in containers

#### **Security Enhancements**
- Enable security linters
- Add vulnerability detection
- Implement security best practices

#### **Advanced Container Features**
- Multi-stage build analysis
- Layer vulnerability attribution
- Enhanced SBOM generation

## 📋 Step-by-Step: Adding a New Extractor

### Example: Adding Kotlin Gradle Support

1. **Create the extractor directory:**
   ```bash
   mkdir -p extractor/filesystem/language/kotlin/gradlekts
   ```

2. **Implement the extractor:**
   ```go
   // extractor/filesystem/language/kotlin/gradlekts/gradlekts.go
   package gradlekts
   
   const Name = "kotlin/gradlekts"
   
   type Extractor struct {
       // Configuration fields
   }
   
   func (e Extractor) Name() string { return Name }
   func (e Extractor) Version() int { return 1 }
   func (e Extractor) Requirements() *plugin.Capabilities {
       return &plugin.Capabilities{OS: plugin.OSAny}
   }
   
   func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
       return strings.HasSuffix(api.Path(), "build.gradle.kts")
   }
   
   func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
       // Parse the file and return packages
   }
   ```

3. **Add comprehensive tests:**
   ```go
   // extractor/filesystem/language/kotlin/gradlekts/gradlekts_test.go
   func TestFileRequired(t *testing.T) { /* ... */ }
   func TestExtract(t *testing.T) { /* ... */ }
   ```

4. **Register the extractor:**
   ```go
   // extractor/filesystem/list/list.go
   KotlinSource = InitMap{gradlekts.Name: {gradlekts.New}}
   ```

5. **Update documentation:**
   ```markdown
   # docs/supported_inventory_types.md
   * Kotlin
     * build.gradle.kts
   ```

## 🛠️ Development Workflow

### 1. **Before Starting**
- Check existing issues for similar work
- Discuss large changes in GitHub issues
- Sign the Google CLA

### 2. **Development Process**
```bash
# Create feature branch
git checkout -b feature/kotlin-gradle-support

# Make changes
# ... implement your feature ...

# Test your changes
make test
make lint

# Commit with clear messages
git commit -m "Add Kotlin Gradle extractor

- Supports build.gradle.kts files
- Extracts dependencies and plugins
- Includes comprehensive tests"

# Push and create PR
git push origin feature/kotlin-gradle-support
```

### 3. **Pull Request Guidelines**
- **Clear title and description**
- **Link to related issues**
- **Include tests for new functionality**
- **Update documentation**
- **Ensure CI passes**

## 🧪 Testing Guidelines

### Unit Tests
```go
func TestExtractor_Extract(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected []*extractor.Package
    }{
        {
            name: "simple_dependency",
            input: `implementation("org.example:library:1.0.0")`,
            expected: []*extractor.Package{
                {
                    Name:    "org.example:library",
                    Version: "1.0.0",
                },
            },
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

### Cross-Platform Tests
```go
func TestExtractor_CrossPlatform(t *testing.T) {
    if runtime.GOOS == "windows" {
        // Windows-specific test logic
    } else {
        // Unix-specific test logic
    }
}
```

## 🎨 Code Style Guidelines

### General Principles
- Follow [Google Go Style Guide](https://google.github.io/styleguide/go/)
- Use 80 character line limit when possible
- Write clear, self-documenting code
- Add comments for complex logic

### Naming Conventions
```go
// Extractor names: ecosystem/format
const Name = "python/requirements"

// Receiver names: consistent across methods
func (e Extractor) Name() string { return Name }
func (e Extractor) Extract(...) { /* ... */ }

// Error handling: descriptive messages
return fmt.Errorf("failed to parse %s: %w", filename, err)
```

### File Organization
```
extractor/filesystem/language/{ecosystem}/{format}/
├── {format}.go          # Main implementation
├── {format}_test.go     # Unit tests
├── testdata/           # Test fixtures
│   ├── simple.txt
│   └── complex.txt
└── README.md           # Format-specific docs
```

## 🔍 Debugging Tips

### Common Issues
1. **Path handling on Windows**
   ```go
   // Use filepath.ToSlash() for virtual filesystems
   path = filepath.ToSlash(path)
   ```

2. **Large file handling**
   ```go
   // Check file size in FileRequired()
   if fileinfo.Size() > maxSize {
       return false
   }
   ```

3. **Context cancellation**
   ```go
   // Check context in long-running operations
   if ctx.Err() != nil {
       return ctx.Err()
   }
   ```

### Debugging Tools
```bash
# Run specific tests
go test -v ./extractor/filesystem/language/python/requirements

# Run with race detection
go test -race ./...

# Profile memory usage
go test -memprofile=mem.prof ./...
```

## 📚 Resources

### Documentation
- [Architecture Overview](../README.md#architecture)
- [New Extractor Guide](new_extractor.md)
- [New Detector Guide](new_detector.md)
- [Style Guide](style_guide.md)

### Code Examples
- **Simple extractor:** `extractor/filesystem/language/python/requirements/`
- **Complex extractor:** `extractor/filesystem/language/java/pomxml/`
- **OS extractor:** `extractor/filesystem/os/dpkg/`
- **Detector:** `detector/weakcredentials/etcshadow/`

### Community
- [GitHub Issues](https://github.com/google/osv-scalibr/issues)
- [Contributing Guidelines](../CONTRIBUTING.md)
- [Code of Conduct](https://opensource.google/conduct/)

## 🎯 Next Steps

1. **Choose your first contribution:**
   - Browse [good first issues](https://github.com/google/osv-scalibr/labels/good%20first%20issue)
   - Pick an ecosystem you're familiar with
   - Start with documentation improvements

2. **Get familiar with the codebase:**
   - Read existing extractors
   - Understand the plugin architecture
   - Run the tests locally

3. **Join the community:**
   - Comment on issues you're interested in
   - Ask questions in GitHub discussions
   - Share your ideas for improvements

Welcome to the OSV-SCALIBR community! We're excited to see your contributions. 🚀