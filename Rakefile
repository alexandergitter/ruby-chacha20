require "bundler/gem_tasks"
require "rake/extensiontask"
require "minitest/test_task"

Rake::ExtensionTask.new "chacha20_bindings" do |ext|
  ext.ext_dir = "ext/chacha20"
end
Minitest::TestTask.create
task test: :compile

task default: :test

task benchmark: :compile do
  require "benchmark"
  require_relative "lib/ruby-chacha20"

  def read_hex(inp)
    [inp.gsub(/\s+/, "")].pack("H*")
  end

  key = read_hex("0000000000000000000000000000000000000000000000000000000000000000")
  nonce = read_hex("0000000000000000")
  bytesize = 1024 * 1024 * 1024
  puts "Benchmark to encrypt 1 GB of data"

  Benchmark.bm do |bm|
    bm.report("ChaCha20#encrypt") { ChaCha20.new(key, nonce).encrypt("\x00".b * bytesize) }
  end
end
