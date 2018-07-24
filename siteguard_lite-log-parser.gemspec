
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "siteguard_lite/log/parser/version"

Gem::Specification.new do |spec|
  spec.name          = "siteguard_lite-log-parser"
  spec.version       = SiteguardLite::Log::Parser::VERSION
  spec.authors       = ["Takatoshi Ono"]
  spec.email         = ["takatoshi.ono@gmail.com"]

  spec.summary       = %q{A log parser for SiteGuard Lite WAF}
  spec.description   = %q{A log parser for SiteGuard Lite WAF}
  spec.homepage      = "https://github.com/pepabo/siteguard_lite-log-parser"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "ltsv"

  spec.add_development_dependency "bundler", "~> 1.16"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
