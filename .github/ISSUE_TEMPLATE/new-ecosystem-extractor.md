---
name: New Ecosystem Extractor
about: Request support for a new package manager or ecosystem
title: 'Add support for [ECOSYSTEM] ([FILE_FORMAT])'
labels: ['enhancement', 'extractor', 'good first issue']
assignees: ''
---

## Ecosystem Information

**Ecosystem Name:** (e.g., Kotlin, Scala, Clojure)
**Package Manager:** (e.g., Gradle, sbt, Leiningen)
**File Format(s):** (e.g., build.gradle.kts, build.sbt, deps.edn)

## File Format Details

**File Extension(s):** (e.g., .kts, .sbt, .edn)
**Typical Location(s):** (e.g., project root, subprojects)
**Documentation:** (link to official format documentation)

## Example Files

Please provide example files showing typical dependency declarations:

```
# Example 1: Simple dependencies
[paste example file content here]
```

```
# Example 2: Complex dependencies with versions, scopes, etc.
[paste example file content here]
```

## Dependency Format

**Dependency Declaration Pattern:**
- How are dependencies declared? (e.g., `implementation("group:artifact:version")`)
- Are there different dependency types/scopes? (e.g., implementation, test, runtime)
- How are versions specified? (e.g., exact, ranges, variables)

**Package Identifier Format:**
- What format do package identifiers use? (e.g., Maven coordinates, npm-style)
- Are there namespaces or groups?
- How should these map to PURL types?

## Implementation Checklist

- [ ] Create extractor in `extractor/filesystem/language/{ecosystem}/{format}/`
- [ ] Implement `FileRequired()` method for file detection
- [ ] Implement `Extract()` method for parsing dependencies
- [ ] Add comprehensive unit tests with example files
- [ ] Handle edge cases (comments, multi-line declarations, etc.)
- [ ] Add extractor to `extractor/filesystem/list/list.go`
- [ ] Update `docs/supported_inventory_types.md`
- [ ] Ensure cross-platform compatibility

## Additional Context

**Priority:** (High/Medium/Low)
**Use Case:** (Why is this ecosystem important to support?)
**Complexity:** (Are there any parsing challenges or special considerations?)

## Related Issues

- Link to any related issues or discussions
- Reference similar extractors that could serve as examples