# OSV-Scalibr Development Guide for AI Agents

This document provides essential information for working with the OSV-Scalibr codebase using AI coding assistants.

## Required Reading

Essential documents to understand before working on this project:

- **[README.md](README.md)** - Project overview, installation, usage examples, and basic plugin information
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Contributor guidelines, CLA requirements, and code review process
- **[docs/style_guide.md](docs/style_guide.md)** - Golang and SCALIBR-specific coding standards and best practices
- **[docs/supported_inventory_types.md](docs/supported_inventory_types.md)** - Complete list of all supported plugins (extractors, detectors, enrichers, annotators)

Plugin development guides:
- **[docs/new_extractor.md](docs/new_extractor.md)** - How to create new extractor plugins
- **[docs/new_detector.md](docs/new_detector.md)** - How to create new detector plugins
- **[docs/new_enricher.md](docs/new_enricher.md)** - How to create new enricher plugins

## Development Guide

### Prerequisites
- Go installed (see https://go.dev/doc/install)
- For protocol buffer changes: `protoc` and `protoc-gen-go`

### Essential Commands

#### Building
```bash
make              # Build the scalibr binary with CGO enabled
make scalibr      # Same as above
make scalibr-static  # Build static binary
```

#### Testing
```bash
make test         # Run all tests with CGO enabled
go test ./...     # Alternative test command
```

#### Code Quality
```bash
make lint         # Run golangci-lint on entire codebase
```

#### Protocol Buffers
```bash
make protos       # Regenerate protocol buffer files (if needed)
```

#### Quick Development Workflow
```bash
# 1. Build and test your changes
make && make test

# 2. Run lint to check code quality
make lint

# 3. Run the binary locally
./scalibr --help
```

### Installation Methods
```bash
# Install latest from source
go install github.com/google/osv-scalibr/binary/scalibr@latest

# Run basic scan
scalibr --result=result.textproto
```

## Architecture Overview

### Project Structure

OSV-SCALIBR follows a plugin-based architecture with these key directories:

#### Core Components
- **`scalibr.go`** - Main library entry point and scan orchestration
- **`binary/`** - Command-line wrapper and binary-specific code
- **`plugin/`** - Core plugin interfaces and capabilities system
- **`fs/`** - File system abstraction layer
- **`inventory/`** - Data structures for software inventory

#### Plugin Types

##### Extractors (`extractor/`)
Extract software inventory (packages, dependencies):
- **`extractor/filesystem/`** - File system-based extractors (scan files/directories)
  - `language/` - Language-specific package managers (npm, pip, cargo, etc.)
  - `os/` - OS package managers (apt, rpm, apk, etc.)
  - `secrets/` - Secret detection extractors
- **`extractor/standalone/`** - System-level extractors (running processes, containers)

##### Detectors (`detector/`)
Detect security findings and vulnerabilities:
- `cis/` - CIS benchmark checks
- `cve/` - Specific CVE detectors
- `govulncheck/` - Go vulnerability checking
- `weakcredentials/` - Weak credential detection
- `endoflife/` - End-of-life software detection

##### Enrichers (`enricher/`)
Augment inventory with additional data:
- `baseimage/` - Container base image analysis
- `reachability/` - Code reachability analysis
- `secrets/` - Secret validation
- `vex/` - VEX (Vulnerability Exploitability eXchange) processing
- `transitivedependency/` - Dependency resolution

##### Annotators (`annotator/`)
Add contextual information to inventory:
- `osduplicate/` - Mark duplicates between OS and language packages
- `noexecutable/` - Mark packages without executables
- `misc/` - Miscellaneous annotations

#### Veles Sub-library (`veles/`)
Standalone secret scanning library:
- **Purpose**: Detect and validate credentials/secrets
- **`detect.go`** - Secret detection engine and detector interfaces
- **`validate.go`** - Secret validation functionality
- **`secrets/`** - Individual secret detectors (API keys, tokens, certificates)
- **Integration**: Used via SCALIBR extractors and enrichers

### Plugin Development Locations

When creating new plugins, add them to:
- **New extractors**: `extractor/filesystem/` or `extractor/standalone/`
- **New detectors**: `detector/`
- **New enrichers**: `enricher/`
- **New annotators**: `annotator/`
- **New secret detectors**: `veles/secrets/`

### Plugin List Files
Plugin registration and metadata:
- `extractor/filesystem/list/list.go` - Filesystem extractor plugins
- `extractor/standalone/list/list.go` - Standalone extractor plugins
- `detector/list/list.go` - Detector plugins
- `annotator/list/list.go` - Annotator plugins
- `enricher/enricherlist/list.go` - Enricher plugins

## Common Workflows

### Issue Creation

This workflow outlines creating comprehensive GitHub Issues that engineers can pick up and address effectively.

#### 1. Research Phase
- **Investigate the problem domain** using WebFetch and research tools
- **Identify existing solutions** and industry standards/best practices
- **Review GitHub documentation** and community resources
- **Examine current codebase** for related patterns or implementations

```bash
# Research existing issues and discussions
gh issue list --label="enhancement" --state=open
gh issue list --search="your-keyword"

# Search codebase for related implementations
rg "pattern-or-function-name" --type go
```

#### 2. Problem Analysis
- **Articulate the specific problem** or need clearly
- **Document current vs desired state**
- **Identify potential risks** and complexity factors
- **Reference authoritative sources** and documentation

#### 3. Solution Design
Research and document 2-3 potential approaches with:
- **Pros**: Benefits and advantages
- **Cons**: Drawbacks, limitations, risks
- **Implementation details**: Key technical considerations
- **Effort estimate**: Rough complexity assessment

#### 4. Success Criteria
- **Define measurable criteria** for completion
- **Include examples** of what "done" looks like
- **Reference external standards** when applicable
- **Ensure testability** and verifiability

#### 5. Deduplicate Issues
```bash
# Check for duplicate or similar issues
gh issue list --search="keyword" --state=all
gh issue list --label="bug,enhancement" --state=open
```
- Review existing issues before creating new ones
- Consider updating existing issues or adding comments instead

#### 6. Issue Structure Template

```markdown
## Problem Statement
[Clear description of the problem and why it needs solving]

## Research
[Summary of research findings with links to authoritative sources]

## Current State
[Description of how things work today]

## Proposed Solutions

### Option 1: [Solution Name]
**Pros:**
- [Benefit 1]
- [Benefit 2]

**Cons:**
- [Limitation 1]
- [Limitation 2]

**Implementation Details:**
- [Key technical consideration 1]
- [Key technical consideration 2]

### Option 2: [Alternative Solution]
[Same structure as Option 1]

## Success Criteria
- [ ] [Specific measurable criterion 1]
- [ ] [Specific measurable criterion 2]
- [ ] [Reference to external compliance/test suite if applicable]

## Resources
- [Link to relevant documentation]
- [Link to related issues or PRs]
- [Link to external standards or specifications]
```

#### 7. Issue Creation
```bash
# Get available labels
gh label list

# Create issue with appropriate labels
gh issue create --title "Your Issue Title" --body-file issue_body.md --label "enhancement,needs-triage"

# Reference related issues
# Use "Closes #123", "Fixes #456", "Related to #789" in description
```

**Essential Labels to Consider:**
- `bug` - Something isn't working
- `enhancement` - New feature or request
- `documentation` - Improvements to documentation
- `good first issue` - Good for newcomers
- `help wanted` - Extra attention needed
- `needs-triage` - Needs initial review

### Issue Completion (PR Creation)

This workflow guides you through implementing solutions and creating pull requests for GitHub issues.

#### 1. Branch Management (MANDATORY)
```bash
# ALWAYS create a feature branch - NEVER work on main
git checkout -b feat/descriptive-feature-name
# Examples: feat/add-npm-extractor, fix/docker-scan-memory-leak
```
**⚠️ WARNING**: Never commit or push directly to main under any circumstances

#### 2. Issue Analysis
```bash
# Fetch and review issue details
gh issue view <issue-number>

# Review linked issues and PRs
gh issue view <issue-number> --web
```
- Create todo list to track all required tasks from issue description
- Research requirements from issue description and linked resources
- Identify success criteria that need to be met

#### 3. Research Phase
- **Study linked documentation** and reference implementations
- **Examine proposed solutions** in context of existing codebase
- **Review existing patterns** for consistency:
  - Plugin interfaces and implementations
  - Error handling patterns
  - Testing approaches
  - Configuration management
- **Fetch external documentation** when needed using WebFetch

```bash
# Search for similar implementations
rg "similar-pattern" --type go
find . -name "*similar*" -type f
```

#### 4. Implementation
Follow OSV-SCALIBR patterns for:
- **Architecture cohesion**: Use existing interfaces and conventions
- **Code style**: Follow [docs/style_guide.md](docs/style_guide.md)
- **Cross-platform support**: Ensure Linux/Windows/Mac compatibility
- **Performance**: Avoid expensive operations in `FileRequired()` methods

**Write tests first** based on issue success criteria when possible

#### 5. Integration
Update necessary files based on plugin type:

**For new extractors:**
```bash
# Add to appropriate list file
extractor/filesystem/list/list.go    # for filesystem extractors
extractor/standalone/list/list.go    # for standalone extractors
```

**For new detectors:**
```bash
detector/list/list.go
```

**For new enrichers:**
```bash
enricher/enricherlist/list.go
```

**For protocol buffer changes:**
```bash
# Update proto files and regenerate
make protos
```

**For CLI changes:**
```bash
# Update CLI-related files under binary/
binary/scalibr/scalibr.go
binary/proto/           # if adding new result types
```

#### 6. Quality Assurance
```bash
# Build the project
make

# Run all tests
make test

# Run linting
make lint

# Test your specific changes
go test ./path/to/your/package/...

# Test cross-platform compatibility if applicable
```

#### 7. Documentation Updates
Update documentation when applicable:
- **README.md**: For new major features or usage changes
- **docs/supported_inventory_types.md**: For new plugin types
- **Code documentation**: Add docstrings to public functions and types
- **Complex logic**: Document expected formats, algorithms, or integrations

#### 8. Commit and PR (MANDATORY)
```bash
# Stage your changes
git add .

# Commit with descriptive message
git commit -s -m "feat: add npm package extractor

Implements comprehensive npm package detection including:
- package.json parsing with dependency resolution
- node_modules directory scanning
- yarn.lock and package-lock.json support

- Add npm extractor to filesystem extractors
- Add tests with sample package files
- Update documentation with supported npm features

Fixes #<issue-number>

🤖 Generated with [{agent name}]({website})"

# Push feature branch (NEVER push to main)
git push -u origin feat/descriptive-feature-name

# Create PR for review
gh pr create --title "feat: add npm package extractor" --body "## Summary
Implements comprehensive npm package detection as requested in #<issue-number>

## Changes
- Added npm extractor with support for package.json, yarn.lock, package-lock.json
- Integrated with filesystem extractor list
- Added comprehensive test suite
- Updated documentation

## Testing
- [ ] All existing tests pass
- [ ] New tests cover edge cases
- [ ] Manual testing with real npm projects

🤖 Generated with [{agent name}]({website})"
```

**🔴 CRITICAL**: All changes must go through PR review - no exceptions, even for urgent fixes

#### 9. Verification
```bash
# Verify CI checks pass
gh pr checks

# Review PR in browser if needed
gh pr view --web

# Address any review feedback
gh pr review --approve  # only after addressing comments
```

**Final Checklist:**
- [ ] Feature branch created (not main)
- [ ] All tests pass locally
- [ ] Linting passes
- [ ] Documentation updated
- [ ] PR created and linked to issue
- [ ] CI checks passing
- [ ] Ready for review
