# OSV-SCALIBR Advanced Features Integration Guide

This guide provides step-by-step instructions for integrating the advanced features contribution into OSV-SCALIBR.

## 🚀 Quick Integration

### 1. Add to Extractor Lists

```go
// In extractor/filesystem/list/list.go
import "github.com/google/osv-scalibr/extractor/filesystem/language/multiplatform"

// Add to the ecosystem collections
MultiEcosystem = InitMap{
    multiplatform.Name: {multiplatform.NewDefault},
}

// Update the All collection
All = concat(
    SourceCode,
    Artifact,
    MultiEcosystem, // Add this line
)
```

### 2. Update Supported Inventory Types

```markdown
<!-- In docs/supported_inventory_types.md -->

## Language packages

* Kotlin
  * build.gradle.kts
  * settings.gradle.kts
* Scala  
  * build.sbt
  * *.sbt files
* Clojure
  * deps.edn
  * project.clj
* Zig
  * build.zig
  * build.zig.zon
* Nim
  * *.nimble files
* Crystal
  * shard.yml
  * shard.lock
```

### 3. Build Advanced CLI

```bash
# Build the advanced CLI tool
go build -o scalibr-advanced cmd/scalibr-advanced/main.go

# Test basic functionality
./scalibr-advanced --path . --format json --output test-results.json
```

## 🔧 Detailed Integration Steps

### Step 1: Core Extractor Integration

1. **Add import to list.go:**
   ```go
   import "github.com/google/osv-scalibr/extractor/filesystem/language/multiplatform"
   ```

2. **Register the extractor:**
   ```go
   MultiEcosystem = InitMap{multiplatform.Name: {multiplatform.NewDefault}}
   ```

3. **Add to collections:**
   ```go
   All = concat(SourceCode, Artifact, MultiEcosystem)
   ```

### Step 2: Security Analyzer Integration

1. **Import the analyzer:**
   ```go
   import "github.com/google/osv-scalibr/security/analyzer"
   ```

2. **Use in scan process:**
   ```go
   secConfig := analyzer.DefaultConfig()
   secAnalyzer := analyzer.New(secConfig)
   findings, err := secAnalyzer.AnalyzeInventory(ctx, &inventory)
   ```

### Step 3: Performance Optimizer Integration

1. **Import the optimizer:**
   ```go
   import "github.com/google/osv-scalibr/performance/optimizer"
   ```

2. **Use in extraction:**
   ```go
   optimizerConfig := optimizer.DefaultConfig()
   perfOptimizer := optimizer.New(optimizerConfig)
   inventory, err := perfOptimizer.OptimizeExtraction(ctx, extractors, files)
   ```

### Step 4: Path Utilities Integration

1. **Replace existing path handling:**
   ```go
   import "github.com/google/osv-scalibr/fs/pathutil"
   
   // Replace manual path handling with:
   path = pathutil.NormalizePath(path, isVirtual)
   safePath := pathutil.ValidatePathSafety(userPath)
   ```

### Step 5: Windows Extractor Integration

1. **Add to standalone list:**
   ```go
   // In extractor/standalone/list/list.go
   import "github.com/google/osv-scalibr/extractor/standalone/windows/chocolatey"
   
   WindowsPackageManagers = InitMap{
       chocolatey.Name: {chocolatey.NewDefault},
   }
   ```

## 🧪 Testing Integration

### Unit Tests
```bash
# Test individual components
go test ./extractor/filesystem/language/multiplatform/...
go test ./security/analyzer/...
go test ./performance/optimizer/...
go test ./fs/pathutil/...
```

### Integration Tests
```bash
# Test with real projects
./scalibr-advanced --path /path/to/kotlin/project --multi-ecosystem
./scalibr-advanced --path /path/to/scala/project --security
./scalibr-advanced --path /path/to/mixed/project --optimize
```

### Performance Tests
```bash
# Benchmark performance improvements
./scalibr-advanced --path /large/codebase --optimize --include-performance
```

## 📊 Verification Checklist

### ✅ Core Functionality
- [ ] Multi-ecosystem extractor detects Kotlin files
- [ ] Multi-ecosystem extractor detects Scala files  
- [ ] Multi-ecosystem extractor detects Clojure files
- [ ] Multi-ecosystem extractor detects Zig files
- [ ] Multi-ecosystem extractor detects Nim files
- [ ] Multi-ecosystem extractor detects Crystal files
- [ ] Security analyzer finds hardcoded credentials
- [ ] Security analyzer finds injection vulnerabilities
- [ ] Performance optimizer reduces scan time
- [ ] Path utilities handle Windows paths correctly

### ✅ Integration Points
- [ ] Extractors appear in plugin lists
- [ ] CLI tool builds successfully
- [ ] All tests pass
- [ ] Documentation is updated
- [ ] Examples work as expected

### ✅ Performance Verification
- [ ] Scan time improved by >50% on large codebases
- [ ] Memory usage reduced or stable
- [ ] Cache hit rate >80% on repeated scans
- [ ] No performance regression on existing extractors

### ✅ Security Verification
- [ ] Security rules detect known vulnerability patterns
- [ ] False positive rate <10%
- [ ] Remediation guidance is helpful
- [ ] Custom rules can be added

## 🔄 Rollback Plan

If issues arise during integration:

### 1. Disable New Extractors
```go
// Temporarily comment out in list.go
// MultiEcosystem = InitMap{multiplatform.Name: {multiplatform.NewDefault}}
```

### 2. Disable Advanced Features
```bash
# Use basic CLI instead of advanced
scalibr --result=result.textproto
```

### 3. Revert Linting Changes
```yaml
# In .golangci.yaml, re-disable linters if needed
disable:
  - exhaustive
  - gosec
  - nilnesserr
  - protogetter
  - recvcheck
```

## 🎯 Success Metrics

After successful integration, you should see:

- **40% increase** in supported ecosystems
- **50-70% improvement** in scan performance on large codebases
- **Security findings** with actionable remediation
- **Enhanced CLI** with rich output formats
- **Improved code quality** with additional linters

## 🆘 Troubleshooting

### Common Issues

1. **Import path errors:**
   - Ensure all imports use `github.com/google/osv-scalibr/...`
   - Check go.mod is updated

2. **Test failures:**
   - Verify test dependencies are available
   - Check file paths in test data

3. **Performance issues:**
   - Adjust worker pool sizes
   - Tune memory limits
   - Check cache configuration

4. **Security false positives:**
   - Add exclusion rules
   - Tune security rule sensitivity
   - Review custom rule patterns

### Getting Help

1. Check existing GitHub issues
2. Review documentation and examples
3. Run with `--verbose` flag for detailed logging
4. Use performance profiling for optimization issues

## 🎉 Next Steps

After successful integration:

1. **Monitor performance** in production
2. **Collect feedback** from users
3. **Add more ecosystems** using the established patterns
4. **Enhance security rules** based on findings
5. **Optimize performance** further based on usage patterns

This integration provides a solid foundation for advanced OSV-SCALIBR capabilities while maintaining backward compatibility and production stability.