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

// Package log defines SCALIBR's logger interface. By default it uses the Go logger
// but it can be replaced with user-defined loggers.
package log

import "log"

// Logger is SCALIBR's logging interface.
type Logger interface {
	// Logs in different log levels, either formatted or unformatted.
	Errorf(format string, args ...any)
	Error(args ...any)
	Warnf(format string, args ...any)
	Warn(args ...any)
	Infof(format string, args ...any)
	Info(args ...any)
	Debugf(format string, args ...any)
	Debug(args ...any)
}

var logger Logger = &DefaultLogger{}

// SetLogger overwrites the default SCALIBR logger with a user specified one.
func SetLogger(l Logger) { logger = l }

// Errorf is the static formatted error logging function.
func Errorf(format string, args ...any) {
	logger.Errorf(format, args...)
}

// Warnf is the static formatted warning logging function.
func Warnf(format string, args ...any) {
	logger.Warnf(format, args...)
}

// Infof is the static formatted info logging function.
func Infof(format string, args ...any) {
	logger.Infof(format, args...)
}

// Debugf is the static formatted debug logging function.
func Debugf(format string, args ...any) {
	logger.Debugf(format, args...)
}

// Error is the static error logging function.
func Error(args ...any) {
	logger.Error(args...)
}

// Warn is the static warning logging function.
func Warn(args ...any) {
	logger.Warn(args...)
}

// Info is the static info logging function.
func Info(args ...any) {
	logger.Info(args...)
}

// Debug is the static debug logging function.
func Debug(args ...any) {
	logger.Debug(args...)
}

// DefaultLogger is the Logger implementation used by default.
// It just logs to stderr using the default Go logger.
type DefaultLogger struct {
	Verbose bool // Whether debug logs should be shown.
}

// Errorf is the formatted error logging function.
func (DefaultLogger) Errorf(format string, args ...any) {
	log.Printf(format, args...)
}

// Warnf is the formatted warning logging function.
func (DefaultLogger) Warnf(format string, args ...any) {
	log.Printf(format, args...)
}

// Infof is the formatted info logging function.
func (DefaultLogger) Infof(format string, args ...any) {
	log.Printf(format, args...)
}

// Debugf is the formatted debug logging function.
func (l *DefaultLogger) Debugf(format string, args ...any) {
	if l.Verbose {
		log.Printf(format, args...)
	}
}

// Error is the error logging function.
func (DefaultLogger) Error(args ...any) {
	log.Println(args...)
}

// Warn is the warning logging function.
func (DefaultLogger) Warn(args ...any) {
	log.Println(args...)
}

// Info is the info logging function.
func (DefaultLogger) Info(args ...any) {
	log.Println(args...)
}

// Debug is the debug logging function.
func (l *DefaultLogger) Debug(args ...any) {
	if l.Verbose {
		log.Println(args...)
	}
}
