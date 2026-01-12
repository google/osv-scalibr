# frozen_string_literal: true

require 'rubygems' unless Object.const_defined?(:Gem)
require File.dirname(__FILE__) + '/lib/example_app/version'

Gem::Specification.new do |spec|
  spec.name = 'example_app_require'
  spec.version = ExampleApp::VERSION
end
