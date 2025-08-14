// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package optimizer provides advanced performance optimization for OSV-SCALIBR scans.
package optimizer

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/stats"
)

// OptimizationStrategy defines different optimization approaches.
type OptimizationStrategy int

const (
	StrategyBalanced OptimizationStrategy = iota
	StrategySpeed
	StrategyMemory
	StrategyThroughput
)

// Config configures the scan optimizer.
type Config struct {
	Strategy             OptimizationStrategy
	MaxConcurrentWorkers int
	EnablePrefiltering   bool
	EnableCaching        bool
	EnableBatching       bool
	BatchSize            int
	CacheSize            int
	MemoryLimit          int64 // bytes
	TimeoutPerFile       time.Duration
}

// DefaultConfig returns an optimized default configuration.
func DefaultConfig() Config {
	numCPU := runtime.NumCPU()
	
	return Config{
		Strategy:             StrategyBalanced,
		MaxConcurrentWorkers: numCPU * 2,
		EnablePrefiltering:   true,
		EnableCaching:        true,
		EnableBatching:       true,
		BatchSize:            100,
		CacheSize:            10000,
		MemoryLimit:          1024 * 1024 * 1024, // 1GB
		TimeoutPerFile:       30 * time.Second,
	}
}

// FileInfo contains metadata about a file for optimization decisions.
type FileInfo struct {
	Path         string
	Size         int64
	Extension    string
	Priority     int
	EstimatedCPU time.Duration
}

// WorkerPool manages concurrent extraction workers.
type WorkerPool struct {
	workers   int
	semaphore chan struct{}
	wg        sync.WaitGroup
}

// NewWorkerPool creates a new worker pool.
func NewWorkerPool(workers int) *WorkerPool {
	return &WorkerPool{
		workers:   workers,
		semaphore: make(chan struct{}, workers),
	}
}

// Submit submits work to the pool.
func (wp *WorkerPool) Submit(ctx context.Context, work func() error) error {
	select {
	case wp.semaphore <- struct{}{}:
		wp.wg.Add(1)
		go func() {
			defer func() {
				<-wp.semaphore
				wp.wg.Done()
			}()
			if err := work(); err != nil {
				log.Errorf("Worker error: %v", err)
			}
		}()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Wait waits for all workers to complete.
func (wp *WorkerPool) Wait() {
	wp.wg.Wait()
}

// Optimizer provides advanced scan optimization capabilities.
type Optimizer struct {
	config      Config
	fileCache   sync.Map
	resultCache sync.Map
	stats       *OptimizationStats
	workerPool  *WorkerPool
}

// OptimizationStats tracks optimization metrics.
type OptimizationStats struct {
	mu                    sync.RWMutex
	FilesProcessed        int64
	FilesSkipped          int64
	CacheHits             int64
	CacheMisses           int64
	TotalProcessingTime   time.Duration
	AverageFileTime       time.Duration
	MemoryUsage           int64
	PeakMemoryUsage       int64
	ExtractorPerformance  map[string]time.Duration
}

// New creates a new scan optimizer.
func New(cfg Config) *Optimizer {
	return &Optimizer{
		config:     cfg,
		stats:      &OptimizationStats{ExtractorPerformance: make(map[string]time.Duration)},
		workerPool: NewWorkerPool(cfg.MaxConcurrentWorkers),
	}
}

// OptimizeExtraction optimizes the extraction process for better performance.
func (o *Optimizer) OptimizeExtraction(ctx context.Context, extractors []filesystem.Extractor, files []FileInfo) (inventory.Inventory, error) {
	start := time.Now()
	defer func() {
		o.stats.mu.Lock()
		o.stats.TotalProcessingTime = time.Since(start)
		if o.stats.FilesProcessed > 0 {
			o.stats.AverageFileTime = o.stats.TotalProcessingTime / time.Duration(o.stats.FilesProcessed)
		}
		o.stats.mu.Unlock()
	}()
	
	// Step 1: Prefilter files if enabled
	if o.config.EnablePrefiltering {
		files = o.prefilterFiles(files, extractors)
		log.Infof("Prefiltering reduced files from %d to %d", len(files), len(files))
	}
	
	// Step 2: Prioritize and batch files
	if o.config.EnableBatching {
		files = o.prioritizeFiles(files)
	}
	
	// Step 3: Process files with optimization
	return o.processFilesOptimized(ctx, extractors, files)
}

// prefilterFiles removes files that are unlikely to contain relevant packages.
func (o *Optimizer) prefilterFiles(files []FileInfo, extractors []filesystem.Extractor) []FileInfo {
	var filtered []FileInfo
	
	// Build a map of file extensions that extractors care about
	relevantExtensions := make(map[string]bool)
	for _, ext := range []string{
		".json", ".xml", ".yml", ".yaml", ".toml", ".lock",
		".gradle", ".sbt", ".clj", ".edn", ".nimble", ".zig",
		".go", ".mod", ".py", ".js", ".ts", ".rb", ".php",
		".java", ".kt", ".scala", ".rs", ".swift", ".dart",
	} {
		relevantExtensions[ext] = true
	}
	
	for _, file := range files {
		// Skip very large files unless they're known package files
		if file.Size > 100*1024*1024 { // 100MB
			if !o.isKnownPackageFile(file.Path) {
				o.stats.mu.Lock()
				o.stats.FilesSkipped++
				o.stats.mu.Unlock()
				continue
			}
		}
		
		// Skip files with irrelevant extensions
		if !relevantExtensions[file.Extension] && !o.isKnownPackageFile(file.Path) {
			o.stats.mu.Lock()
			o.stats.FilesSkipped++
			o.stats.mu.Unlock()
			continue
		}
		
		// Skip common non-package directories
		if o.isNonPackageDirectory(file.Path) {
			o.stats.mu.Lock()
			o.stats.FilesSkipped++
			o.stats.mu.Unlock()
			continue
		}
		
		filtered = append(filtered, file)
	}
	
	return filtered
}

// prioritizeFiles sorts files by processing priority.
func (o *Optimizer) prioritizeFiles(files []FileInfo) []FileInfo {
	// Calculate priority based on file characteristics
	for i := range files {
		files[i].Priority = o.calculateFilePriority(files[i])
	}
	
	// Sort by priority (higher first)
	sort.Slice(files, func(i, j int) bool {
		return files[i].Priority > files[j].Priority
	})
	
	return files
}

// calculateFilePriority assigns a priority score to a file.
func (o *Optimizer) calculateFilePriority(file FileInfo) int {
	priority := 0
	
	// High priority for known package files
	if o.isKnownPackageFile(file.Path) {
		priority += 100
	}
	
	// Medium priority for common dependency files
	if o.isCommonDependencyFile(file.Path) {
		priority += 50
	}
	
	// Lower priority for large files
	if file.Size > 1024*1024 { // 1MB
		priority -= 20
	}
	
	// Higher priority for files in root directories
	if strings.Count(file.Path, "/") <= 2 {
		priority += 30
	}
	
	return priority
}

// processFilesOptimized processes files with various optimizations.
func (o *Optimizer) processFilesOptimized(ctx context.Context, extractors []filesystem.Extractor, files []FileInfo) (inventory.Inventory, error) {
	var mu sync.Mutex
	var allPackages []*extractor.Package
	
	// Process files in batches
	batchSize := o.config.BatchSize
	if batchSize <= 0 {
		batchSize = len(files)
	}
	
	for i := 0; i < len(files); i += batchSize {
		end := i + batchSize
		if end > len(files) {
			end = len(files)
		}
		
		batch := files[i:end]
		
		// Process batch concurrently
		for _, file := range batch {
			file := file // Capture loop variable
			
			err := o.workerPool.Submit(ctx, func() error {
				packages, err := o.processFile(ctx, extractors, file)
				if err != nil {
					log.Debugf("Error processing %s: %v", file.Path, err)
					return nil // Don't fail the entire batch
				}
				
				if len(packages) > 0 {
					mu.Lock()
					allPackages = append(allPackages, packages...)
					mu.Unlock()
				}
				
				o.stats.mu.Lock()
				o.stats.FilesProcessed++
				o.stats.mu.Unlock()
				
				return nil
			})
			
			if err != nil {
				return inventory.Inventory{}, err
			}
		}
		
		// Wait for batch to complete before starting next batch
		o.workerPool.Wait()
		
		// Check memory usage and GC if needed
		if o.config.MemoryLimit > 0 {
			o.checkMemoryUsage()
		}
	}
	
	return inventory.Inventory{Packages: allPackages}, nil
}

// processFile processes a single file with caching and optimization.
func (o *Optimizer) processFile(ctx context.Context, extractors []filesystem.Extractor, file FileInfo) ([]*extractor.Package, error) {
	// Check cache first
	if o.config.EnableCaching {
		if cached, ok := o.resultCache.Load(file.Path); ok {
			o.stats.mu.Lock()
			o.stats.CacheHits++
			o.stats.mu.Unlock()
			
			if packages, ok := cached.([]*extractor.Package); ok {
				return packages, nil
			}
		}
	}
	
	o.stats.mu.Lock()
	o.stats.CacheMisses++
	o.stats.mu.Unlock()
	
	// Create a timeout context for this file
	fileCtx, cancel := context.WithTimeout(ctx, o.config.TimeoutPerFile)
	defer cancel()
	
	var allPackages []*extractor.Package
	
	// Try each extractor
	for _, extractor := range extractors {
		start := time.Now()
		
		// Check if extractor is interested in this file
		// Note: This is a simplified check - in real implementation,
		// we'd need to create a proper FileAPI implementation
		if !o.extractorInterestedInFile(extractor, file) {
			continue
		}
		
		// Extract packages (simplified - real implementation would need proper ScanInput)
		// packages, err := extractor.Extract(fileCtx, scanInput)
		// For now, we'll simulate the extraction
		packages := o.simulateExtraction(extractor, file)
		
		duration := time.Since(start)
		
		// Track extractor performance
		o.stats.mu.Lock()
		o.stats.ExtractorPerformance[extractor.Name()] += duration
		o.stats.mu.Unlock()
		
		allPackages = append(allPackages, packages...)
	}
	
	// Cache results
	if o.config.EnableCaching {
		o.resultCache.Store(file.Path, allPackages)
	}
	
	return allPackages, nil
}

// Helper methods

func (o *Optimizer) isKnownPackageFile(path string) bool {
	knownFiles := []string{
		"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
		"requirements.txt", "Pipfile.lock", "poetry.lock", "pyproject.toml",
		"go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
		"pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
		"composer.json", "composer.lock", "Gemfile", "Gemfile.lock",
		"deps.edn", "project.clj", "build.sbt", "build.zig",
	}
	
	base := filepath.Base(path)
	for _, known := range knownFiles {
		if base == known {
			return true
		}
	}
	
	return false
}

func (o *Optimizer) isCommonDependencyFile(path string) bool {
	patterns := []string{
		"*.lock", "*.toml", "*.gradle", "*.sbt", "*.nimble",
		"requirements*.txt", "setup.py", "pyproject.toml",
	}
	
	base := filepath.Base(path)
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, base); matched {
			return true
		}
	}
	
	return false
}

func (o *Optimizer) isNonPackageDirectory(path string) bool {
	nonPackageDirs := []string{
		"node_modules", "vendor", ".git", ".svn", ".hg",
		"target", "build", "dist", "out", "bin",
		"__pycache__", ".pytest_cache", ".tox",
		"coverage", "htmlcov", "docs", "doc",
	}
	
	for _, dir := range nonPackageDirs {
		if strings.Contains(path, "/"+dir+"/") || strings.HasSuffix(path, "/"+dir) {
			return true
		}
	}
	
	return false
}

func (o *Optimizer) extractorInterestedInFile(extractor filesystem.Extractor, file FileInfo) bool {
	// Simplified check - in real implementation, we'd use FileAPI
	// For now, just check file extension matching
	ext := file.Extension
	name := extractor.Name()
	
	// Simple heuristic mapping
	if strings.Contains(name, "python") && (ext == ".py" || ext == ".txt" || ext == ".lock") {
		return true
	}
	if strings.Contains(name, "javascript") && (ext == ".json" || ext == ".lock" || ext == ".yaml") {
		return true
	}
	if strings.Contains(name, "java") && (ext == ".xml" || ext == ".gradle" || ext == ".lock") {
		return true
	}
	if strings.Contains(name, "go") && (ext == ".mod" || ext == ".sum") {
		return true
	}
	
	return false
}

func (o *Optimizer) simulateExtraction(extractor filesystem.Extractor, file FileInfo) []*extractor.Package {
	// This is a simulation - real implementation would call extractor.Extract()
	// For demonstration, return empty packages
	return []*extractor.Package{}
}

func (o *Optimizer) checkMemoryUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	currentUsage := int64(m.Alloc)
	
	o.stats.mu.Lock()
	o.stats.MemoryUsage = currentUsage
	if currentUsage > o.stats.PeakMemoryUsage {
		o.stats.PeakMemoryUsage = currentUsage
	}
	o.stats.mu.Unlock()
	
	// Force GC if memory usage is high
	if currentUsage > o.config.MemoryLimit {
		log.Debugf("Memory usage high (%d bytes), forcing GC", currentUsage)
		runtime.GC()
	}
}

// GetStats returns the current optimization statistics.
func (o *Optimizer) GetStats() OptimizationStats {
	o.stats.mu.RLock()
	defer o.stats.mu.RUnlock()
	
	// Create a copy to avoid race conditions
	stats := OptimizationStats{
		FilesProcessed:       o.stats.FilesProcessed,
		FilesSkipped:         o.stats.FilesSkipped,
		CacheHits:            o.stats.CacheHits,
		CacheMisses:          o.stats.CacheMisses,
		TotalProcessingTime:  o.stats.TotalProcessingTime,
		AverageFileTime:      o.stats.AverageFileTime,
		MemoryUsage:          o.stats.MemoryUsage,
		PeakMemoryUsage:      o.stats.PeakMemoryUsage,
		ExtractorPerformance: make(map[string]time.Duration),
	}
	
	for k, v := range o.stats.ExtractorPerformance {
		stats.ExtractorPerformance[k] = v
	}
	
	return stats
}

// PrintStats prints optimization statistics.
func (o *Optimizer) PrintStats() {
	stats := o.GetStats()
	
	fmt.Printf("\n=== Optimization Statistics ===\n")
	fmt.Printf("Files Processed: %d\n", stats.FilesProcessed)
	fmt.Printf("Files Skipped: %d\n", stats.FilesSkipped)
	fmt.Printf("Cache Hits: %d\n", stats.CacheHits)
	fmt.Printf("Cache Misses: %d\n", stats.CacheMisses)
	fmt.Printf("Total Processing Time: %v\n", stats.TotalProcessingTime)
	fmt.Printf("Average File Time: %v\n", stats.AverageFileTime)
	fmt.Printf("Peak Memory Usage: %d bytes\n", stats.PeakMemoryUsage)
	
	if len(stats.ExtractorPerformance) > 0 {
		fmt.Printf("\nExtractor Performance:\n")
		for name, duration := range stats.ExtractorPerformance {
			fmt.Printf("  %s: %v\n", name, duration)
		}
	}
}