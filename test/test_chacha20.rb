require "test_helper"

class TestChaCha20 < Minitest::Test
  include TestHelper

  def test_seek
    c = ChaCha20.new("\x00" * 32, "\x00" * 8)
    assert_equal 0, c.send(:get_counter)
    assert_equal 0, c.instance_variable_get(:@block_offset)

    c.seek(63)
    assert_equal 0, c.send(:get_counter)
    assert_equal 63, c.instance_variable_get(:@block_offset)

    c.seek(64)
    assert_equal 1, c.send(:get_counter)
    assert_equal 0, c.instance_variable_get(:@block_offset)

    c.seek(0x0102030405060708)
    assert_equal 1134747809224732, c.send(:get_counter)
    assert_equal 8, c.instance_variable_get(:@block_offset)
  end

  def test_encrypt_correctly_advances_byte_position
    c = ChaCha20.new("\x00" * 32, "\x00" * 8)

    c.seek(128)
    c.encrypt("")
    assert_equal 2, c.send(:get_counter)
    assert_equal 0, c.instance_variable_get(:@block_offset)

    c.seek(0)
    c.encrypt("\x00" * 13)
    assert_equal 0, c.send(:get_counter)
    assert_equal 13, c.instance_variable_get(:@block_offset)

    c.seek(0)
    c.encrypt("\x00" * 128)
    assert_equal 2, c.send(:get_counter)
    assert_equal 0, c.instance_variable_get(:@block_offset)

    c.seek(0)
    c.encrypt("\x00" * 130)
    assert_equal 2, c.send(:get_counter)
    assert_equal 2, c.instance_variable_get(:@block_offset)

    c.seek(127)
    c.encrypt("\x00" * 3)
    assert_equal 2, c.send(:get_counter)
    assert_equal 2, c.instance_variable_get(:@block_offset)

    c.seek(120)
    c.encrypt("\x00" * 120)
    assert_equal 3, c.send(:get_counter)
    assert_equal 48, c.instance_variable_get(:@block_offset)
  end

  def vectors
    [
      {
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "0000000000000000",
        counter: 0,
        block_offset: 0,
        keystream: "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee65869f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f2d09a0e663266ce1ae7ed1081968a0758e718e997bd362c6b0c34634a9a0b35d012737681f7b5d0f281e3afde458bc1e73d2d313c9cf94c05ff3716240a248f21320a058d7b3566bd520daaa3ed2bf0ac5b8b120fb852773c3639734b45c91a42dd4cb83f8840d2eedb158131062ac3f1f2cf8ff6dcd1856e86a1e6c3167167ee5a688742b47c5adfb"
      },
      {
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "0000000000000000",
        counter: 0,
        block_offset: 15,
        keystream: "28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee65869f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f2d09a0e663266ce1ae7ed1081968a0758e718e997bd362c6b0c34634a9a0b35d012737681f7b5d0f281e3afde458bc1e73"
      },
      {
        key: "0000000000000000000000000000000000000000000000000000000000000001",
        nonce: "0000000000000000",
        counter: 0,
        block_offset: 0,
        keystream: "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963"
      },
      {
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "0000000000000001",
        counter: 0,
        block_offset: 0,
        keystream: "de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e31afab757"
      },
      {
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "0100000000000000",
        counter: 0,
        block_offset: 0,
        keystream: "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b"
      },
      {
        key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        nonce: "0001020304050607",
        counter: 0,
        block_offset: 0,
        keystream: "f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a"
      },
      {
        key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        nonce: "0001020304050607",
        counter: 2,
        block_offset: 0,
        keystream: "9db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d7"
      }
    ]
  end

  def test_keystream_matches_test_vectors
    vectors.each do |vector|
      key = read_hex(vector[:key])
      nonce = read_hex(vector[:nonce])
      counter = vector[:counter]
      block_offset = vector[:block_offset]
      keystream = read_hex(vector[:keystream])

      cipher = ChaCha20.new(key, nonce)
      cipher.seek(counter * 64 + block_offset)

      assert_equal keystream.unpack("H*"), cipher.encrypt("\x00".b * keystream.bytesize).unpack("H*")
    end
  end
end
