---
name: Linting Improvement
about: Enable a disabled linter or fix linting violations
title: 'Enable [LINTER_NAME] linter'
labels: ['enhancement', 'code-quality', 'linting']
assignees: ''
---

## Linter Information

**Linter Name:** (e.g., exhaustive, gosec, nilnesserr)
**Current Status:** Currently disabled in `.golangci.yaml`
**Related Issue:** #274

## Linter Purpose

**What it checks:** (Brief description of what this linter validates)
**Why it's important:** (Security, correctness, maintainability benefits)

## Current Violations

Run the linter to identify current violations:
```bash
golangci-lint run --disable-all --enable=[LINTER_NAME] ./...
```

**Estimated violation count:** (Run the command and report the number)
**Common violation patterns:** (List the most frequent types of violations)

## Implementation Plan

### Phase 1: Analysis
- [ ] Run linter to catalog all violations
- [ ] Categorize violations by type and severity
- [ ] Identify false positives that need exclusions
- [ ] Estimate effort required for fixes

### Phase 2: Fixes
- [ ] Fix violations in small, focused commits
- [ ] Add exclusions for legitimate false positives
- [ ] Update code to follow linter requirements
- [ ] Ensure all tests pass after fixes

### Phase 3: Enable
- [ ] Remove linter from `disable` list in `.golangci.yaml`
- [ ] Add any necessary configuration for the linter
- [ ] Verify CI passes with linter enabled
- [ ] Update documentation if needed

## Example Violations

```go
// BEFORE (violation example)
switch status {
case StatusA:
    return "A"
case StatusB:
    return "B"
// Missing StatusC case - exhaustive violation
}

// AFTER (fixed)
switch status {
case StatusA:
    return "A"
case StatusB:
    return "B"
case StatusC:
    return "C"
default:
    return "UNKNOWN"
}
```

## Exclusion Strategy

**Files/packages that may need exclusions:**
- Generated code (e.g., `*.pb.go`)
- Third-party code
- Test files (if appropriate)
- Legacy code (temporary exclusions)

**Exclusion configuration:**
```yaml
issues:
  exclude-rules:
    - path: generated/
      linters:
        - [LINTER_NAME]
```

## Success Criteria

- [ ] Linter enabled without violations
- [ ] CI passes consistently
- [ ] No false positive noise
- [ ] Code quality improved
- [ ] Team understands new requirements

## Rollback Plan

If enabling the linter causes issues:
1. Add temporary exclusions for problematic areas
2. Create follow-up issues for excluded violations
3. Enable gradually (per-package or per-violation-type)

## Related Work

- [ ] Check if similar work is being done in related projects
- [ ] Coordinate with other linting improvement efforts
- [ ] Consider impact on contributor workflow