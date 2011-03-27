# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run 'rake gemspec'
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{warden_facebook}
  s.version = "0.0.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Daniel Schierbeck"]
  s.date = %q{2010-12-30}
  s.description = %q{TODO: longer description of your gem}
  s.email = %q{daniel.schierbeck@gmail.com}
  s.extra_rdoc_files = [
    "LICENSE",
    "README.markdown"
  ]
  s.files = [
    ".document",
    "Gemfile",
    "Gemfile.lock",
    "LICENSE",
    "README.markdown",
    "Rakefile",
    "VERSION",
    "config.ru",
    "lib/warden/facebook.rb",
    "lib/warden/facebook/proxy.rb",
    "lib/warden/facebook/strategy.rb",
    "lib/warden/facebook/user.rb",
    "test/app.rb",
    "test/helper.rb",
    "test/strategy_test.rb",
    "test/user_test.rb"
  ]
  s.homepage = %q{http://github.com/dasch/warden_facebook}
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.7}
  s.summary = %q{TODO: one-line summary of your gem}
  s.test_files = [
    "test/app.rb",
    "test/helper.rb",
    "test/strategy_test.rb",
    "test/user_test.rb"
  ]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<warden>, [">= 0"])
      s.add_runtime_dependency(%q<oauth2>, [">= 0"])
      s.add_runtime_dependency(%q<json>, [">= 0"])
      s.add_development_dependency(%q<shotgun>, [">= 0"])
    else
      s.add_dependency(%q<warden>, [">= 0"])
      s.add_dependency(%q<oauth2>, [">= 0"])
      s.add_dependency(%q<json>, [">= 0"])
      s.add_dependency(%q<shotgun>, [">= 0"])
    end
  else
    s.add_dependency(%q<warden>, [">= 0"])
    s.add_dependency(%q<oauth2>, [">= 0"])
    s.add_dependency(%q<json>, [">= 0"])
    s.add_dependency(%q<shotgun>, [">= 0"])
  end
end
