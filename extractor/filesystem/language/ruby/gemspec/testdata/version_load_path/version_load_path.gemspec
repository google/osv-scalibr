# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'example_app/version'

Gem::Specification.new do |spec|
  spec.name = 'example_app'
  spec.version = ExampleApp::VERSION
end
