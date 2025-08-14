# OSV‑SCALIBR Contribution Implementation Plan

## 🎯 Project Overview
**Project**: OSV‑SCALIBR (Software Composition Analysis Library)  
**Goal**: Improve code quality, expand ecosystem support, and enhance cross‑platform compatibility.  
**Target**: Contributors new and experienced.  
**Platform**: Go library (Linux, Windows, macOS).  

## 📋 High‑Priority Tasks (Quick Wins)

| # | Task | Description | Expected Outcome |
|---|------|-------------|----------------|
| 1 | **Enable `exhaustive` linter** | Remove from `disable` list, run linter, fix missing switch cases. | No `exhaustive` violations. |
| 2 | **Enable `nilnesserr` linter** | Fix functions returning nil error with non‑nil values. | Clean `nilnesserr` results. |
| 3 | **Enable `protogetter` linter** | Regenerate proto files or add missing getters. | No missing getter warnings. |
| 4 | **Enable `recvcheck` linter** | Standardize receiver names across methods. | Consistent receiver naming. |
| 5 | **Enable `gosec` linter** | Fix security issues (hard‑coded secrets, command injection). | Pass security linting. |
| 6 | **Add Kotlin extractor** | Implement `gradlekts` extractor (already present) and add tests. | Kotlin support in extractor list. |
| 7 | **Cross‑platform path handling** | Ensure `filepath.ToSlash` usage, normalize Windows paths. | No path‑related lint failures. |
| 8 | **Documentation updates** | Add sections to `CONTRIBUTION_ROADMAP.md` and `docs/new_contributor_guide.md`. | Improved contributor docs. |

## 🏗️ Technical Architecture

- **Language**: Go (1.22+).  
- **Build**: `make` (build, test, lint).  
- **CI**: GitHub Actions (Linux, macOS, Windows).  
- **Linter**: `golangci-lint` (configured in `.golangci.yaml`).  

### Repository Structure (relevant parts)

```
/osv-scalibr
├── .golangci.yaml          # Linter config
├── TOOLS.md               # Development tools list
├── CONTRIBUTION_ROADMAP.md # Contribution opportunities
├── LINTING_IMPROVEMENT_PLAN.md # Linting plan
├── extractor/
│   └── filesystem/
│       └── language/kotlin/gradlekts/   # Kotlin extractor
├── docs/
│   └── new_contributor_guide.md
├── Makefile
└── ... (other packages)
```

## 📦 Implementation Steps

### Phase 1 – Linter Enablement
1. **Enable `exhaustive`**  
   - Run `golangci-lint run --disable-all --enable=exhaustive ./...`  
   - Fix missing cases, add `//exhaustive:ignore` where needed.  
2. **Enable `nilnesserr`**  
   - Run `golangci-lint run --enable=nilnesserr ./...`  
   - Add proper error returns.  
3. **Enable `protogetter`**  
   - Regenerate proto files: `make protos`.  
   - Add missing getters if needed.  
4. **Enable `recvcheck`**  
   - Standardize receiver names (`e` for `Extractor`, `d` for `Detector`).  
5. **Enable `gosec`**  
   - Run `golangci-lint run --enable=gosec ./...`  
   - Fix security warnings (e.g., command injection).  

### Phase 2 – Kotlin Extractor
1. Review `extractor/filesystem/language/kotlin/gradlekts/gradlekts.go`.  
2. Add unit tests (`gradlekts_test.go`) covering:
   - File detection (`FileRequired`).  
   - Extraction logic (parse `build.gradle.kts`).  
3. Ensure `FileRequired` uses simple string checks (no regex).  
4. Add extractor to `extractor/filesystem/list/list.go`.  

### Phase 3 – Cross‑Platform Path Handling
1. Search for `filepath.Join` vs hard‑coded `/`.  
2. Replace with `filepath.ToSlash` for virtual FS.  
3. Add unit tests for path utilities (`fs/pathutil`).  

### Phase 4 – Documentation
1. Update `CONTRIBUTION_ROADMAP.md` with new tasks.  
2. Add “Enabling Linters” section to `docs/new_contributor_guide.md`.  
3. Add “Kotlin Extractor” guide.  

## 📊 Success Metrics
- **All 5 linters enabled** with zero violations.  
- **Kotlin extractor** passes `go test ./...`.  
- **No path‑related lint errors**.  
- **Documentation** updated and reviewed.  

## 📚 Resources
- [golangci‑lint docs](https://golangci-lint.run/usage/linters/)  
- [OSV‑SCALIBR style guide](docs/style_guide.md)  
- [Contribution guidelines](CONTRIBUTING.md)  

## 📅 Timeline
| Week | Tasks |
|------|------|
| 1 | Enable `exhaustive`, `nilnesserr`. |
| 2 | Enable `protogetter`, `recvcheck`. |
| 3 | Enable `gosec`, fix security issues. |
| 4 | Add Kotlin extractor tests. |
| 5 | Cross‑platform path fixes. |
| 6 | Documentation updates. |
| 7 | Final CI run, PR creation. |

---

**Next Steps**  
1. Run `go install` to get `golangci-lint` (if not already installed).  
2. Execute `golangci-lint run ./...` and share any violations.  
3. Follow the phased plan above.
