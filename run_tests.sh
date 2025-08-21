#!/bin/bash

# OSV-SCALIBR Advanced Features Test Suite
# This script runs comprehensive tests for all new components

set -e

echo "🧪 OSV-SCALIBR Advanced Features Test Suite"
echo "============================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo -e "\n${YELLOW}Running: $test_name${NC}"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if eval "$test_command"; then
        echo -e "${GREEN}✅ PASSED: $test_name${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}❌ FAILED: $test_name${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Verify Go environment
echo "🔍 Verifying Go environment..."
if ! command -v go &> /dev/null; then
    echo -e "${RED}❌ Go is not installed or not in PATH${NC}"
    echo "Please install Go 1.24+ to run tests"
    exit 1
fi

GO_VERSION=$(go version | cut -d' ' -f3)
echo -e "${GREEN}✅ Go version: $GO_VERSION${NC}"

# Check if we're in the right directory
if [ ! -f "go.mod" ]; then
    echo -e "${RED}❌ Not in OSV-SCALIBR root directory${NC}"
    echo "Please run this script from the OSV-SCALIBR root directory"
    exit 1
fi

echo -e "${GREEN}✅ In OSV-SCALIBR root directory${NC}"

# Unit Tests
echo -e "\n🧪 Running Unit Tests"
echo "====================="

# Test path utilities
run_test "Path Utilities" "go test ./fs/pathutil/... -v"

# Test multiplatform ecosystem detector
run_test "Multi-Ecosystem Detector" "go test ./extractor/filesystem/language/multiplatform/... -v"

# Test Kotlin extractor
run_test "Kotlin Gradle Extractor" "go test ./extractor/filesystem/language/kotlin/gradlekts/... -v"

# Test Windows Chocolatey extractor (if on Windows)
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    run_test "Windows Chocolatey Extractor" "go test ./extractor/standalone/windows/chocolatey/... -v"
else
    echo -e "${YELLOW}⏭️  Skipping Windows Chocolatey tests (not on Windows)${NC}"
fi

# Test security analyzer
run_test "Security Analyzer" "go test ./security/analyzer/... -v"

# Test performance optimizer
run_test "Performance Optimizer" "go test ./performance/optimizer/... -v"

# Test extracttest utilities
run_test "Extract Test Utilities" "go test ./testing/extracttest/... -v"

# Build Tests
echo -e "\n🔨 Running Build Tests"
echo "======================"

# Test advanced CLI build
run_test "Advanced CLI Build" "go build -o /tmp/scalibr-advanced ./cmd/scalibr-advanced/"

# Integration Tests
echo -e "\n🔗 Running Integration Tests"
echo "============================"

# Create test project structures
mkdir -p /tmp/test-projects/{kotlin,scala,clojure,zig,nim,crystal}

# Kotlin test project
cat > /tmp/test-projects/kotlin/build.gradle.kts << 'EOF'
plugins {
    id("org.jetbrains.kotlin.jvm") version "1.8.0"
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib:1.8.0")
    testImplementation("junit:junit:4.13.2")
}
EOF

# Scala test project
cat > /tmp/test-projects/scala/build.sbt << 'EOF'
libraryDependencies ++= Seq(
  "org.scala-lang" % "scala-library" % "2.13.8",
  "org.scalatest" %% "scalatest" % "3.2.12" % Test
)
EOF

# Clojure test project
cat > /tmp/test-projects/clojure/deps.edn << 'EOF'
{:deps {org.clojure/clojure {:mvn/version "1.11.1"}
        ring/ring-core {:mvn/version "1.9.5"}}}
EOF

# Test ecosystem detection
run_test "Kotlin Project Detection" "/tmp/scalibr-advanced --path /tmp/test-projects/kotlin --format json --output /tmp/kotlin-results.json"
run_test "Scala Project Detection" "/tmp/scalibr-advanced --path /tmp/test-projects/scala --format json --output /tmp/scala-results.json"
run_test "Clojure Project Detection" "/tmp/scalibr-advanced --path /tmp/test-projects/clojure --format json --output /tmp/clojure-results.json"

# Verify results contain expected packages
if [ -f "/tmp/kotlin-results.json" ]; then
    if grep -q "kotlin-stdlib" /tmp/kotlin-results.json; then
        echo -e "${GREEN}✅ Kotlin packages detected correctly${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}❌ Kotlin packages not detected${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
fi

# Performance Tests
echo -e "\n⚡ Running Performance Tests"
echo "============================"

# Test with performance optimization
run_test "Performance Optimization" "/tmp/scalibr-advanced --path . --optimize --include-performance --format text"

# Security Tests
echo -e "\n🛡️  Running Security Tests"
echo "=========================="

# Create test file with security issues
mkdir -p /tmp/security-test
cat > /tmp/security-test/vulnerable.py << 'EOF'
import os

# Hardcoded password (should be detected)
password = "hardcoded123"

# SQL injection vulnerability (should be detected)
query = "SELECT * FROM users WHERE id = " + user_id

# Command injection (should be detected)
os.system("rm -rf " + user_input)
EOF

run_test "Security Analysis" "/tmp/scalibr-advanced --path /tmp/security-test --security --format json --output /tmp/security-results.json"

# Verify security findings
if [ -f "/tmp/security-results.json" ]; then
    if grep -q "HARDCODED_PASSWORD\|SQL_INJECTION\|COMMAND_INJECTION" /tmp/security-results.json; then
        echo -e "${GREEN}✅ Security vulnerabilities detected correctly${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}❌ Security vulnerabilities not detected${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
fi

# Linting Tests
echo -e "\n📝 Running Linting Tests"
echo "========================"

# Test with enabled linters
run_test "Enhanced Linting" "golangci-lint run ./fs/pathutil/... ./extractor/filesystem/language/multiplatform/..."

# Cleanup
echo -e "\n🧹 Cleaning up test files..."
rm -rf /tmp/test-projects /tmp/security-test /tmp/*-results.json /tmp/scalibr-advanced

# Summary
echo -e "\n📊 Test Summary"
echo "==============="
echo -e "Total Tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "${RED}Failed: $FAILED_TESTS${NC}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All tests passed! Ready for commit.${NC}"
    exit 0
else
    echo -e "\n${RED}❌ Some tests failed. Please review and fix issues.${NC}"
    exit 1
fi