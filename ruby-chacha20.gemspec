Gem::Specification.new do |spec|
  spec.name = "ruby-chacha20"
  spec.version = "0.1.1"
  spec.authors = ["Alexander Gitter"]
  spec.email = ["contact@agitter.de"]

  spec.summary = "ChaCha20 stream cipher algorithm."
  spec.homepage = "https://github.com/alexandergitter/ruby-chacha20"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage

  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/chacha20/extconf.rb"]

  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rake-compiler", "~> 1.0"
  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "memory_profiler", "~> 1.0"
end
