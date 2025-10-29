# frozen_string_literal: true

require_relative 'lib/example_app/version' if defined?(ExampleApp)

Gem::Specification.new do |spec|
  spec.name = 'example_app_conditional'
  spec.version = ExampleApp::VERSION
end
