package gemspec

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestExtractRequireTargets(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		{
			name: "simple literal",
			line: "require_relative 'lib/foo/version'",
			want: []string{"lib/foo/version"},
		},
		{
			name: "polish comments and condition",
			line: "require_relative 'lib/foo/version' if defined?(Foo)",
			want: []string{"lib/foo/version"},
		},
		{
			name: "file join",
			line: "require_relative File.join('lib', 'foo', 'version')",
			want: []string{"lib/foo/version"},
		},
		{
			name: "expand path",
			line: "require_relative File.expand_path('lib/foo/version', __dir__)",
			want: []string{"lib/foo/version"},
		},
		{
			name: "dirname plus",
			line: "require_relative File.dirname(__FILE__) + '/lib/foo/version'",
			want: []string{"lib/foo/version"},
		},
		{
			name: "dirname plus nested join",
			line: "require_relative File.dirname(__FILE__) + '/' + File.join('lib', 'foo', 'version.rb')",
			want: []string{"lib/foo/version.rb"},
		},
		{
			name: "plain require literal ignored",
			line: "require 'rubygems'",
			want: nil,
		},
		{
			name: "plain require project path",
			line: "require File.dirname(__FILE__) + '/lib/foo/version'",
			want: []string{"lib/foo/version"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRequireTargets(tt.line)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("extractRequireTargets diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseDirnameConcat(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want string
	}{
		{
			name: "simple",
			expr: "File.dirname(__FILE__) + '/lib/foo/version'",
			want: "lib/foo/version",
		},
		{
			name: "with parent",
			expr: "File.dirname(__FILE__) + '/../lib/foo/version'",
			want: "../lib/foo/version",
		},
		{
			name: "multiple literals",
			expr: "File.dirname(__FILE__) + '/../lib/' + 'foo/version'",
			want: "../lib/foo/version",
		},
		{
			name: "no dirname",
			expr: "'lib/foo' + 'version'",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseDirnameConcat(tt.expr); got != tt.want {
				t.Fatalf("parseDirnameConcat(%q) = %q, want %q", tt.expr, got, tt.want)
			}
		})
	}
}

func TestSplitOnPlus(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want []string
	}{
		{
			name: "basic",
			expr: "a + b + c",
			want: []string{"a", "b", "c"},
		},
		{
			name: "with strings",
			expr: "File.dirname(__FILE__) + '/lib' + '/foo'",
			want: []string{"File.dirname(__FILE__)", "'/lib'", "'/foo'"},
		},
		{
			name: "skip plus in string",
			expr: "File.dirname(__FILE__) + 'lib+'",
			want: []string{"File.dirname(__FILE__)", "'lib+'"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, splitOnPlus(tt.expr)); diff != "" {
				t.Fatalf("splitOnPlus diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRequireAccumulator(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  []string
	}{
		{
			name:  "single line",
			lines: []string{"require_relative 'lib/foo'"},
			want:  []string{"lib/foo"},
		},
		{
			name: "multi-line",
			lines: []string{
				"require_relative File.join(",
				"  'lib',",
				"  'foo',",
				"  'version'",
				")",
			},
			want: []string{"lib/foo/version"},
		},
		{
			name: "multi-line with blank",
			lines: []string{
				"require_relative(",
				"  File.dirname(__FILE__) + '/lib/foo'",
				")",
			},
			want: []string{"lib/foo"},
		},
		{
			name: "plain require multi-line",
			lines: []string{
				"require File.join(",
				"  'lib',",
				"  'foo',",
				"  'version'",
				")",
			},
			want: []string{"lib/foo/version"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acc := &requireAccumulator{}
			var got []string
			for _, line := range tt.lines {
				got = append(got, acc.Add(line)...)
			}
			got = append(got, acc.Flush()...)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("requireAccumulator diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRequireStatementComplete(t *testing.T) {
	tests := []struct {
		expr string
		want bool
	}{
		{"require_relative 'lib'", true},
		{"require_relative File.join('lib',", false},
		{"require_relative File.join('lib', 'foo')", true},
		{"require_relative 'lib' if condition", true},
	}
	for _, tt := range tests {
		if got := requireStatementComplete(tt.expr); got != tt.want {
			t.Fatalf("requireStatementComplete(%q) = %v, want %v", tt.expr, got, tt.want)
		}
	}
}

func TestParseFileJoin(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want string
	}{
		{"literals", "File.join('lib', 'foo', 'version')", "lib/foo/version"},
		{"mixed spacing", "File.join( 'lib', 'foo.rb' )", "lib/foo.rb"},
		{"with non literal", "File.join('lib', var)", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseFileJoin(tt.expr); got != tt.want {
				t.Fatalf("parseFileJoin(%q) = %q, want %q", tt.expr, got, tt.want)
			}
		})
	}
}

func TestParseFileExpand(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want string
	}{
		{"literal", "File.expand_path('lib/foo', __dir__)", "lib/foo"},
		{"with join", "File.expand_path(File.join('lib', 'foo.rb'), __FILE__)", "lib/foo.rb"},
		{"unsupported", "File.expand_path(variable, __dir__)", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseFileExpand(tt.expr); got != tt.want {
				t.Fatalf("parseFileExpand(%q) = %q, want %q", tt.expr, got, tt.want)
			}
		})
	}
}

func TestParseQuotedLiteral(t *testing.T) {
	tests := []struct {
		expr string
		want string
		ok   bool
	}{
		{"'foo'", "foo", true},
		{"\"bar\"", "bar", true},
		{"'escaped\\'quote'", "escaped'quote", true},
		{"foo", "", false},
	}
	for _, tt := range tests {
		got, ok := parseQuotedLiteral(tt.expr)
		if got != tt.want || ok != tt.ok {
			t.Fatalf("parseQuotedLiteral(%q) = (%q, %v), want (%q, %v)", tt.expr, got, ok, tt.want, tt.ok)
		}
	}
}

func TestStripInlineComment(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"require 'foo' # comment", "require 'foo'"},
		{"require 'foo#bar'", "require 'foo#bar'"},
		{"  # only comment", ""},
	}
	for _, tt := range tests {
		if got := stripInlineComment(tt.line); got != tt.want {
			t.Fatalf("stripInlineComment(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestTrimRubyTrailingCondition(t *testing.T) {
	tests := []struct {
		expr string
		want string
	}{
		{"foo if bar", "foo"},
		{"foo unless baz", "foo"},
		{"foo", "foo"},
	}
	for _, tt := range tests {
		if got := trimRubyTrailingCondition(tt.expr); got != tt.want {
			t.Fatalf("trimRubyTrailingCondition(%q) = %q, want %q", tt.expr, got, tt.want)
		}
	}
}

func TestRequireKeyword(t *testing.T) {
	tests := []struct {
		expr string
		want string
	}{
		{"require_relative 'foo'", "require_relative"},
		{"require 'foo'", "require"},
		{"puts 'foo'", ""},
	}
	for _, tt := range tests {
		if got := requireKeyword(tt.expr); got != tt.want {
			t.Fatalf("requireKeyword(%q) = %q, want %q", tt.expr, got, tt.want)
		}
	}
}

func TestLooksLikeProjectPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"lib/foo", true},
		{"./foo", true},
		{"foo.rb", true},
		{"json", false},
	}
	for _, tt := range tests {
		if got := looksLikeProjectPath(tt.path); got != tt.want {
			t.Fatalf("looksLikeProjectPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestAppendUnique(t *testing.T) {
	got := appendUnique([]string{"foo"}, "foo", "bar", "")
	want := []string{"foo", "bar"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("appendUnique diff (-want +got):\n%s", diff)
	}
}

func TestExtractCallArguments(t *testing.T) {
	tests := []struct {
		name   string
		expr   string
		prefix string
		want   string
		ok     bool
	}{
		{"simple", "File.join('a', 'b')", "File.join", "'a', 'b'", true},
		{"nested", "File.join(File.join('a'), 'b')", "File.join", "File.join('a'), 'b'", true},
		{"mismatch", "Other('a')", "File.join", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := extractCallArguments(tt.expr, tt.prefix)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("extractCallArguments(%q, %q) = (%q, %v), want (%q, %v)", tt.expr, tt.prefix, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestSplitArgs(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want []string
	}{
		{"basic", "'a', 'b'", []string{"'a'", "'b'"}},
		{"with nested", "File.join('a'), 'b'", []string{"File.join('a')", "'b'"}},
		{"single", "'a'", []string{"'a'"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, splitArgs(tt.expr)); diff != "" {
				t.Fatalf("splitArgs diff (-want +got):\n%s", diff)
			}
		})
	}
}
