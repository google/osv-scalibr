# frozen_string_literal: true

require_relative File.dirname(__FILE__) + '/lib/example_app/version'

Gem::Specification.new do |spec|
  spec.name = 'example_app_dirname'
  spec.version = ExampleApp::VERSION
end
