#!/usr/bin/env ruby

require 'base64'
require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'securerandom'
require 'cgi'

class Cryptor
  def initialize(algorithm, key_length)
    key = SecureRandom.random_bytes(key_length)
    @cipher = Jason::Math::Cryptography::Cipher.new(algorithm, key)
    @initialization_vector = key.dup
  end

  def encrypt(plain_text)
    @cipher.initialization_vector = @initialization_vector
    @cipher.encrypt(plain_text)
  end

  def decrypt(cipher_text)
    @cipher.initialization_vector = @initialization_vector
    @cipher.decrypt(cipher_text)
  end
end

cryptor = Cryptor.new(:aes_128_cbc, 16)
block_size = Jason::Math::Cryptography::Cipher.block_size(cryptor)
puts "block size: #{block_size}"
ecb = Jason::Math::Cryptography::Cipher.detect_ecb?(cryptor.encrypt("A".b * 48))
puts "ecb? #{ecb}"

original_clear_text = "j" * (block_size * 3 - 1)
original_cipher_text = cryptor.encrypt(original_clear_text)

blocks = original_cipher_text.to_blocks(block_size)
zero_block = "\x00" * block_size

crafted_cipher_text = blocks[0] + zero_block + original_cipher_text
crafted_clear_text = cryptor.decrypt(crafted_cipher_text)

blocks = crafted_clear_text.to_blocks(block_size)

key = blocks[0] ^ blocks[2]
print "recovered key: "
pp key

print "original key: "
pp cryptor.instance_variable_get(:@initialization_vector)
