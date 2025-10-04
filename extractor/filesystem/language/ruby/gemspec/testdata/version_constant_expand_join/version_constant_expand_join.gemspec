# frozen_string_literal: true

require_relative File.expand_path(File.join('lib', 'example_app', 'version.rb'), __FILE__)

Gem::Specification.new do |spec|
  spec.name = 'example_app_expand_join'
  spec.version = ExampleApp::VERSION
end
