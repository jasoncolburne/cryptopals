#!/usr/bin/env ruby

require 'base64'
require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'securerandom'

base64_string = <<EOT
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
EOT

class Encryptor
  def initialize(algorithm, key_length, secret_string, initialization_vector = nil)
    key = SecureRandom.random_bytes(key_length)
    @cipher = Jason::Math::Cryptography::Cipher.new(algorithm, key)
    @random_prefix = SecureRandom.random_bytes(SecureRandom.random_number(16) + 16)
    @secret_string = secret_string
    @initialization_vector = initialization_vector
  end

  def encrypt(plain_text)
    message = @random_prefix + plain_text + @secret_string
    @cipher.encrypt(message, @initialization_vector)
  end
end

encryptor = Encryptor.new(:aes_192_cbc, 24, base64_string.base64_to_byte_string, "\x00" * 16)
block_size = Jason::Math::Cryptography::Cipher.block_size(encryptor)
puts "block size: #{block_size}"
ecb = Jason::Math::Cryptography::Cipher.detect_ecb?(encryptor.encrypt("A".b * 48))
puts "ecb? #{ecb}"
# exit(1) unless ecb

extra_length = Jason::Math::Cryptography::Cipher.count_clear_text_extra_bytes(encryptor, block_size)
prefix_length = Jason::Math::Cryptography::Cipher.count_clear_text_prefix_bytes(encryptor, block_size)
secret_length = extra_length - prefix_length

secret_string = ""
secret_length.times do |i|
  base_clear_text = "A".b * ((-secret_string.length - prefix_length - 1) % block_size)
  length = prefix_length + base_clear_text.length + secret_string.length
  target = encryptor.encrypt(base_clear_text)[0..length]

  (0..255).each do |n|
    char = n.chr
    potential_match = encryptor.encrypt(base_clear_text + secret_string + char)[0..length]

    if potential_match == target
      print char
      secret_string << char
      break
    end
  end
end
