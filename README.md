# ChaCha20

A Ruby wrapper for DJBs ChaCha20 implementation (C code in the `/ext` folder). Based off/inspired by
https://github.com/dubek/salsa20-ruby. Supports arbitrary seeking inside the keystream.

**NOTE**: This is not intended to be used in production software. Use for hobby projects only. This Gem does encryption
only, it does not provide any kind of message authentication or integrity checking.

## Installation

For the time being, this is not on rubygems.org. Point your Gemfile to this repository.

## Usage

Initialize a new cipher with a 32-byte key and an 8-byte nonce (both bytestrings of class `String`):

```ruby
cipher = ChaCha20.new(key, nonce)
```

Alternatively, you can set the nonce at a later point in time:

```ruby
cipher = ChaCha20.new(key)
cipher.init_nonce(nonce)  # Returns the ChaCha20 object itself
                          # It will raise if nonce has already been set
```

**Warning**: Do not reuse the nonce value, since this will compromise the security of the encryption. If you need to encrypt
multiple messages, use a different nonce for each message.

You can then encrypt or decrypt data with the `encrypt` and `decrypt` methods:

```ruby
ciphertext = cipher.encrypt(plaintext)
plaintext = cipher.decrypt(ciphertext)
```

Note that these methods advance the internal position inside the key stream, so you can keep calling them for chunk-wise
de-/encryption. If you want to jump to a specific byte-position in the key stream, you can use the `seek` method:

```ruby
cipher.seek(4711)
```
