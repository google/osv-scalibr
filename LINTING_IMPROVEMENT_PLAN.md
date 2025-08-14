# Linting Improvement Plan (Issue #274)

This document outlines the step-by-step plan to enable the currently disabled linters in OSV-SCALIBR.

## 🎯 Current Status

The following linters are disabled with TODO comments in `.golangci.yaml`:

```yaml
- exhaustive       # TODO(#274): work on enabling this
- gosec            # TODO(#274): work on enabling this
- nilnesserr       # TODO(#274): work on enabling this
- protogetter      # TODO(#274): work on enabling this
- recvcheck        # TODO(#274): work on enabling this
```

## 📋 Implementation Plan

### Phase 1: Enable `exhaustive` Linter

**What it does:** Ensures switch statements are exhaustive for enums/constants.

**Steps:**
1. Enable only `exhaustive` linter
2. Run linter to identify violations
3. Fix violations by:
   - Adding missing cases to switch statements
   - Adding default cases where appropriate
   - Using `//exhaustive:ignore` comment for intentional omissions

**Expected violations:** Enum switches in plugin status, OS types, network types

### Phase 2: Enable `nilnesserr` Linter

**What it does:** Checks for nil error returns that should be non-nil.

**Steps:**
1. Enable `nilnesserr` linter
2. Identify functions returning `(T, error)` where nil error with non-nil T is suspicious
3. Fix by:
   - Returning proper errors
   - Adjusting function signatures
   - Adding error checks

**Expected violations:** Parser functions, file operations

### Phase 3: Enable `protogetter` Linter

**What it does:** Checks for missing getters in protocol buffer structs.

**Steps:**
1. Enable `protogetter` linter
2. Identify missing getter methods in proto-generated code
3. Fix by:
   - Regenerating proto files with proper options
   - Adding manual getters if needed
   - Excluding generated files if appropriate

**Expected violations:** Files in `binary/proto/` directory

### Phase 4: Enable `recvcheck` Linter

**What it does:** Checks for consistent receiver names in methods.

**Steps:**
1. Enable `recvcheck` linter
2. Identify inconsistent receiver names
3. Fix by:
   - Standardizing receiver names (e.g., `e` for `Extractor`)
   - Using consistent patterns across the codebase

**Expected violations:** Method receivers across all packages

### Phase 5: Enable `gosec` Linter (Security)

**What it does:** Identifies security vulnerabilities in Go code.

**Steps:**
1. Enable `gosec` linter
2. Identify security issues:
   - Hardcoded credentials
   - Unsafe file operations
   - SQL injection risks
   - Command injection risks
   - Weak cryptography
3. Fix by:
   - Removing hardcoded secrets
   - Adding input validation
   - Using secure alternatives
   - Adding security comments for false positives

**Expected violations:** File operations, command execution, credential handling

## 🔧 Implementation Commands

### Step 1: Test Individual Linters

```bash
# Test exhaustive linter only
golangci-lint run --disable-all --enable=exhaustive ./...

# Test nilnesserr linter only  
golangci-lint run --disable-all --enable=nilnesserr ./...

# Test protogetter linter only
golangci-lint run --disable-all --enable=protogetter ./...

# Test recvcheck linter only
golangci-lint run --disable-all --enable=recvcheck ./...

# Test gosec linter only
golangci-lint run --disable-all --enable=gosec ./...
```

### Step 2: Enable in Configuration

For each linter, remove from the `disable` list in `.golangci.yaml`:

```yaml
# Before
disable:
  - exhaustive       # TODO(#274): work on enabling this

# After  
disable:
  # - exhaustive     # ✅ Enabled in Phase 1
```

## 🎯 Expected Violation Types

### Exhaustive Linter Violations

```go
// BEFORE (violation)
switch status.Status {
case ScanStatusSucceeded:
    return "SUCCESS"
case ScanStatusFailed:
    return "FAILED"
// Missing ScanStatusPartiallySucceeded case
}

// AFTER (fixed)
switch status.Status {
case ScanStatusSucceeded:
    return "SUCCESS"
case ScanStatusFailed:
    return "FAILED"
case ScanStatusPartiallySucceeded:
    return "PARTIAL"
default:
    return "UNKNOWN"
}
```

### Nilnesserr Linter Violations

```go
// BEFORE (violation)
func parseFile(path string) (*Package, error) {
    // ... parsing logic
    return pkg, nil // Should return error if pkg is nil
}

// AFTER (fixed)
func parseFile(path string) (*Package, error) {
    // ... parsing logic
    if pkg == nil {
        return nil, fmt.Errorf("failed to parse package from %s", path)
    }
    return pkg, nil
}
```

### Gosec Linter Violations

```go
// BEFORE (violation)
cmd := exec.Command("sh", "-c", userInput) // G204: Command injection

// AFTER (fixed)
cmd := exec.Command("sh", "-c", filepath.Clean(userInput)) // With validation
```

## 📊 Success Metrics

- [ ] All 5 linters enabled without violations
- [ ] CI passes with new linting rules
- [ ] No security vulnerabilities detected by gosec
- [ ] Consistent code style across codebase
- [ ] Documentation updated to reflect new standards

## 🚨 Rollback Plan

If enabling a linter causes too many violations:

1. **Temporary exclusions:** Add specific exclusions to `.golangci.yaml`
2. **Gradual enablement:** Enable for specific packages first
3. **Issue tracking:** Create separate issues for large violation sets

Example exclusion:
```yaml
issues:
  exclude-rules:
    - path: legacy/
      linters:
        - gosec
    - text: "G204" # Specific gosec rule
      linters:
        - gosec
```

## 🔄 Continuous Improvement

After enabling all linters:

1. **Monitor CI:** Ensure new code doesn't introduce violations
2. **Team training:** Educate contributors on new linting rules
3. **Documentation:** Update style guide with linting requirements
4. **Automation:** Consider pre-commit hooks for linting

## 📚 Resources

- [golangci-lint linters documentation](https://golangci-lint.run/usage/linters/)
- [gosec security rules](https://securecodewarrior.github.io/gosec/)
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)

---

**Note:** This plan should be executed incrementally, with each phase in a separate PR to make reviews manageable.