# OSV-SCALIBR Contribution Roadmap

This document outlines actionable contribution opportunities for OSV-SCALIBR, organized by impact and complexity.

## 🎯 High Impact, Low Complexity (Quick Wins)

### 1. Enable Disabled Linters (Issue #274)

**Current Status:** 5 linters disabled with TODO comments
**Impact:** Improved code quality, security, and maintainability
**Effort:** Medium (requires fixing existing violations)

**Linters to Enable:**
- `exhaustive` - Ensures exhaustive switch statements
- `gosec` - Security-focused linting
- `nilnesserr` - Nil error checking
- `protogetter` - Protocol buffer getter checking  
- `recvcheck` - Receiver method checking

**Action Plan:**
1. Enable one linter at a time
2. Fix violations in small, focused PRs
3. Update `.golangci.yaml` configuration
4. Ensure CI passes

### 2. Missing Ecosystem Support (Issue #457)

**Current Gap:** Several popular ecosystems not supported
**Impact:** Broader language coverage
**Effort:** Low-Medium per ecosystem

**Missing Ecosystems:**
- **Kotlin** (build.gradle.kts files)
- **Scala** (build.sbt, project files)
- **Clojure** (deps.edn, project.clj)
- **Zig** (build.zig files)
- **Nim** (*.nimble files)
- **Crystal** (shard.yml, shard.lock)
- **OCaml** (dune-project, opam files)
- **F#** (paket files)

**Implementation Template Available:** Yes, follow existing patterns

### 3. Cross-Platform Path Handling

**Current Issues:** Windows path handling inconsistencies
**Impact:** Better Windows support
**Effort:** Low-Medium

**Areas to Fix:**
- Consistent use of `filepath.ToSlash()` for virtual filesystems
- Windows drive letter normalization
- Container path mapping on Windows

## 🚀 High Impact, Medium Complexity

### 4. Windows Container Support (Issue #953)

**Current Status:** Not supported
**Impact:** Major platform expansion
**Effort:** High

**Requirements:**
- Windows container layer analysis
- Windows-specific path handling in containers
- Registry access in container contexts
- Cross-platform container filesystem abstraction

### 5. New Package Manager Support

**Missing Package Managers:**
- **vcpkg** (C++ package manager)
- **Bazel** (BUILD files)
- **Buck2** (BUCK files)
- **Meson** (meson.build)
- **CMake** (CMakeLists.txt with find_package)
- **Chocolatey** (Windows package manager)
- **Scoop** (Windows package manager)
- **Winget** (Windows package manager)

### 6. Enhanced Windows OS Support

**Current Windows Extractors:**
- `dismpatch` - DISM patch extraction
- `ospackages` - OS package extraction
- `regosversion` - Registry OS version
- `regpatchlevel` - Registry patch level

**Missing Windows Features:**
- MSI package extraction
- Windows Store app detection
- PowerShell module detection
- Windows Update history
- Installed certificates

## 🔧 Medium Impact, Low Complexity

### 7. Performance Optimizations

**Current Bottlenecks:**
- `FileRequired()` called for every file
- No parallel extraction
- Large file handling inefficiencies

**Optimization Opportunities:**
- Parallel extraction for independent extractors
- File type pre-filtering
- Streaming parsers for large files
- Better inode limit handling

### 8. Enhanced Error Handling

**Current Issues:**
- Inconsistent error messages
- Limited error context
- No error recovery mechanisms

**Improvements:**
- Structured error types
- Better error context
- Graceful degradation
- Error aggregation

### 9. Documentation Improvements

**Missing Documentation:**
- Cross-platform development guide
- Performance tuning guide
- Security best practices
- Plugin development templates

## 🛡️ Security & Quality

### 10. Security Enhancements

**Enable Security Linting:**
- Enable `gosec` linter
- Fix security violations
- Add security tests

**Security Gaps:**
- Input validation in parsers
- Path traversal protection
- Resource exhaustion protection
- Credential exposure prevention

### 11. Test Coverage Improvements

**Missing Test Scenarios:**
- Cross-platform test cases
- Large file handling tests
- Error condition testing
- Performance regression tests

## 🔬 Advanced Features

### 12. Container Security Enhancements

**Current:** Basic layer attribution
**Needed:** Advanced container analysis

**Enhancement Areas:**
- Multi-stage build analysis
- Layer vulnerability attribution
- Base image security scanning
- Container runtime security

### 13. Enhanced Observability

**Current Stats Collection:** Basic metrics
**Missing Observability:**
- Detailed performance metrics
- Memory usage tracking
- Error rate monitoring
- Plugin success rates

## 📋 Implementation Priority

### Phase 1: Foundation (1-2 months)
1. ✅ Enable `exhaustive` linter
2. ✅ Enable `nilnesserr` linter  
3. ✅ Fix cross-platform path issues
4. ✅ Add missing ecosystem: Kotlin

### Phase 2: Expansion (2-3 months)
1. ✅ Enable `gosec` linter
2. ✅ Add Windows package managers
3. ✅ Performance optimizations
4. ✅ Enhanced error handling

### Phase 3: Advanced (3-4 months)
1. ✅ Windows container support
2. ✅ Advanced container analysis
3. ✅ Enhanced observability
4. ✅ Security improvements

## 🎯 Getting Started

### For New Contributors:
1. **Start with documentation improvements**
2. **Pick a missing ecosystem to implement**
3. **Enable one disabled linter**
4. **Add cross-platform tests**

### For Experienced Contributors:
1. **Tackle Windows container support**
2. **Implement performance optimizations**
3. **Add advanced security features**
4. **Enhance container analysis**

## 📚 Resources

- [New Extractor Guide](docs/new_extractor.md)
- [New Detector Guide](docs/new_detector.md)
- [Style Guide](docs/style_guide.md)
- [Contributing Guidelines](CONTRIBUTING.md)

---

**Note:** This roadmap is living document. Priorities may shift based on community needs and project direction.