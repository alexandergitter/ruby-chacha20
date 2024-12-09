$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "ruby-chacha20"

require "minitest/autorun"

module TestHelper
  def read_hex(inp)
    [inp.gsub(/\s+/, "")].pack("H*")
  end
end
