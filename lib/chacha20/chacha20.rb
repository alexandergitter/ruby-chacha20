class ChaCha20
  def initialize(key, nonce)
    raise TypeError, "key must be a String" unless key.is_a? String
    raise TypeError, "nonce must be a String" unless nonce.is_a? String

    raise ArgumentError, "key must be 32 bytes" unless key.bytesize == 32
    raise ArgumentError, "nonce must be 8 bytes" unless nonce.bytesize == 8

    @block_offset = 0

    init_context(key, nonce)
  end

  def seek(position)
    raise ArgumentError, "position must be a non-negative integer" unless position.is_a?(Integer) && position >= 0

    set_counter(position / 64)
    @block_offset = position % 64
  end

  def encrypt(input)
    raise ArgumentError, "plaintext must be a string" unless input.is_a?(String)
    length = input.bytesize

    result = "\x00".b * @block_offset + input
    result = encrypt_or_decrypt(result)
    result = result.slice(@block_offset, length)

    @block_offset = (@block_offset + length) % 64
    set_counter(get_counter - 1) unless @block_offset.zero?

    result
  end

  alias_method :decrypt, :encrypt
end
