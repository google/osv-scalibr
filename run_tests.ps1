# OSV-SCALIBR Advanced Features Test Suite (PowerShell)
# This script runs comprehensive tests for all new components

param(
    [switch]$Verbose = $false
)

# Colors for output
$Red = "Red"
$Green = "Green"
$Yellow = "Yellow"

# Test counters
$TotalTests = 0
$PassedTests = 0
$FailedTests = 0

function Run-Test {
    param(
        [string]$TestName,
        [scriptblock]$TestCommand
    )
    
    Write-Host "`nRunning: $TestName" -ForegroundColor $Yellow
    $script:TotalTests++
    
    try {
        $result = & $TestCommand
        if ($LASTEXITCODE -eq 0 -or $result) {
            Write-Host "✅ PASSED: $TestName" -ForegroundColor $Green
            $script:PassedTests++
        } else {
            Write-Host "❌ FAILED: $TestName" -ForegroundColor $Red
            $script:FailedTests++
        }
    } catch {
        Write-Host "❌ FAILED: $TestName - $($_.Exception.Message)" -ForegroundColor $Red
        $script:FailedTests++
    }
}

Write-Host "🧪 OSV-SCALIBR Advanced Features Test Suite" -ForegroundColor $Yellow
Write-Host "============================================"

# Verify Go environment
Write-Host "`n🔍 Verifying Go environment..."
try {
    $goVersion = go version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Go version: $goVersion" -ForegroundColor $Green
    } else {
        throw "Go not found"
    }
} catch {
    Write-Host "❌ Go is not installed or not in PATH" -ForegroundColor $Red
    Write-Host "Please install Go 1.24+ to run tests"
    exit 1
}

# Check if we're in the right directory
if (-not (Test-Path "go.mod")) {
    Write-Host "❌ Not in OSV-SCALIBR root directory" -ForegroundColor $Red
    Write-Host "Please run this script from the OSV-SCALIBR root directory"
    exit 1
}

Write-Host "✅ In OSV-SCALIBR root directory" -ForegroundColor $Green

# Syntax and Import Verification
Write-Host "`n🔍 Running Syntax and Import Verification" -ForegroundColor $Yellow
Write-Host "=========================================="

# Check Go syntax for all new files
$newGoFiles = @(
    "fs/pathutil/pathutil.go",
    "fs/pathutil/pathutil_test.go",
    "extractor/filesystem/language/multiplatform/ecosystem_detector.go",
    "extractor/filesystem/language/multiplatform/parsers.go",
    "extractor/filesystem/language/multiplatform/ecosystem_detector_test.go",
    "extractor/filesystem/language/kotlin/gradlekts/gradlekts.go",
    "extractor/filesystem/language/kotlin/gradlekts/gradlekts_test.go",
    "security/analyzer/security_analyzer.go",
    "performance/optimizer/scan_optimizer.go",
    "cmd/scalibr-advanced/main.go",
    "extractor/standalone/windows/chocolatey/chocolatey.go",
    "extractor/standalone/windows/chocolatey/chocolatey_dummy.go",
    "testing/extracttest/fake_file_api.go"
)

foreach ($file in $newGoFiles) {
    if (Test-Path $file) {
        Run-Test "Syntax Check: $file" {
            go fmt $file > $null 2>&1
            return $LASTEXITCODE -eq 0
        }
    } else {
        Write-Host "⚠️  File not found: $file" -ForegroundColor $Yellow
    }
}

# Build Tests
Write-Host "`n🔨 Running Build Tests" -ForegroundColor $Yellow
Write-Host "======================"

# Test if packages can be built
$packages = @(
    "./fs/pathutil",
    "./extractor/filesystem/language/multiplatform",
    "./extractor/filesystem/language/kotlin/gradlekts",
    "./security/analyzer",
    "./performance/optimizer",
    "./testing/extracttest"
)

foreach ($pkg in $packages) {
    if (Test-Path $pkg) {
        Run-Test "Build: $pkg" {
            go build $pkg > $null 2>&1
            return $LASTEXITCODE -eq 0
        }
    }
}

# Test advanced CLI build
Run-Test "Advanced CLI Build" {
    go build -o scalibr-advanced.exe ./cmd/scalibr-advanced/ > $null 2>&1
    $success = $LASTEXITCODE -eq 0
    if (Test-Path "scalibr-advanced.exe") {
        Remove-Item "scalibr-advanced.exe" -Force
    }
    return $success
}

# Unit Tests (if Go test works)
Write-Host "`n🧪 Running Unit Tests" -ForegroundColor $Yellow
Write-Host "====================="

foreach ($pkg in $packages) {
    if (Test-Path $pkg) {
        Run-Test "Unit Tests: $pkg" {
            go test $pkg -v > $null 2>&1
            return $LASTEXITCODE -eq 0
        }
    }
}

# File Structure Verification
Write-Host "`n📁 Verifying File Structure" -ForegroundColor $Yellow
Write-Host "============================"

$requiredFiles = @(
    "PRODUCTION_READY_CONTRIBUTION.md",
    "INTEGRATION_GUIDE.md",
    "COMMIT_VERIFICATION.md",
    "CONTRIBUTION_ROADMAP.md",
    "docs/new_contributor_guide.md",
    ".github/ISSUE_TEMPLATE/new-ecosystem-extractor.md",
    ".github/ISSUE_TEMPLATE/linting-improvement.md"
)

foreach ($file in $requiredFiles) {
    Run-Test "File Exists: $file" {
        return Test-Path $file
    }
}

# Documentation Verification
Write-Host "`n📚 Verifying Documentation" -ForegroundColor $Yellow
Write-Host "=========================="

Run-Test "Documentation Completeness" {
    $docFiles = Get-ChildItem -Path "." -Filter "*.md" -Recurse | Where-Object { $_.Name -like "*CONTRIBUTION*" -or $_.Name -like "*INTEGRATION*" }
    return $docFiles.Count -ge 3
}

# License Header Verification
Write-Host "`n📄 Verifying License Headers" -ForegroundColor $Yellow
Write-Host "============================="

foreach ($file in $newGoFiles) {
    if (Test-Path $file) {
        Run-Test "License Header: $file" {
            $content = Get-Content $file -Raw
            return $content -match "Copyright 2025 Google LLC"
        }
    }
}

# Import Path Verification
Write-Host "`n📦 Verifying Import Paths" -ForegroundColor $Yellow
Write-Host "========================="

foreach ($file in $newGoFiles) {
    if (Test-Path $file) {
        Run-Test "Import Paths: $file" {
            $content = Get-Content $file -Raw
            # Check that imports use github.com/google/osv-scalibr
            if ($content -match 'import.*".*"') {
                $imports = [regex]::Matches($content, '"([^"]*github\.com/google/osv-scalibr[^"]*)"')
                if ($imports.Count -gt 0) {
                    # All OSV-SCALIBR imports should be consistent
                    foreach ($import in $imports) {
                        if (-not ($import.Groups[1].Value -match '^github\.com/google/osv-scalibr')) {
                            return $false
                        }
                    }
                }
                return $true
            }
            return $true  # No imports is also valid
        }
    }
}

# Summary
Write-Host "`n📊 Test Summary" -ForegroundColor $Yellow
Write-Host "==============="
Write-Host "Total Tests: $TotalTests"
Write-Host "Passed: $PassedTests" -ForegroundColor $Green
Write-Host "Failed: $FailedTests" -ForegroundColor $Red

if ($FailedTests -eq 0) {
    Write-Host "`n🎉 All tests passed! Ready for commit." -ForegroundColor $Green
    exit 0
} else {
    Write-Host "`n❌ Some tests failed. Please review and fix issues." -ForegroundColor $Red
    exit 1
}