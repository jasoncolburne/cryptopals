#!/usr/bin/env ruby

require 'base64'
require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'securerandom'
require 'cgi'

class Cryptor
  PREFIX = "comment1=cooking%20MCs;userdata=".b
  SUFFIX = ";comment2=%20like%20a%20pound%20of%20bacon".b

  def initialize(algorithm, key_length)
    key = SecureRandom.random_bytes(key_length)
    @cipher = Jason::Math::Cryptography::Cipher.new(algorithm, key)
    @initialization_vector = SecureRandom.random_bytes(16)
  end

  def encrypt(plain_text)
    message = PREFIX + CGI.escape(plain_text) + SUFFIX
    @cipher.initialization_vector = @initialization_vector
    @cipher.encrypt(message)
  end

  def decrypt_and_check_admin(cipher_text)
    @cipher.initialization_vector = @initialization_vector
    clear_text = @cipher.decrypt(cipher_text)
    clear_text.include?(';admin=true;')
  end
end

cryptor = Cryptor.new(:aes_192_cbc, 24)
block_size = Jason::Math::Cryptography::Cipher.block_size(cryptor)
puts "block size: #{block_size}"
ecb = Jason::Math::Cryptography::Cipher.detect_ecb?(cryptor.encrypt("A".b * 48))
puts "ecb? #{ecb}"

extra_length = Jason::Math::Cryptography::Cipher.count_clear_text_extra_bytes(cryptor, block_size)
puts "non-chosen clear text length: #{extra_length}"
prefix_length = Jason::Math::Cryptography::Cipher.count_clear_text_prefix_bytes(cryptor, block_size)
puts "non-chosen clear text prefix length: #{prefix_length}"

puts

chosen_clear_text = "foo;admin=true"
print "chosen clear text: "
pp chosen_clear_text
admin = cryptor.decrypt_and_check_admin(cryptor.encrypt("foo;admin=true"))
puts "admin: #{admin}"

puts

chosen_clear_text = 'j' * ((prefix_length / block_size + 2) * block_size - prefix_length)
puts "chosen clear text: #{chosen_clear_text}"
injected_clear_text = ";admin=true"
injected_clear_text = 'j' * (block_size - injected_clear_text.length) + injected_clear_text
puts "injected clear text: #{injected_clear_text}"
injection_range = ((prefix_length + chosen_clear_text.length - 2 * block_size)..(prefix_length + chosen_clear_text.length - block_size - 1))
xor_mask = "j" * block_size ^ injected_clear_text
print "xor mask: "
pp xor_mask
cipher_text = cryptor.encrypt(chosen_clear_text)
print "cipher text:"
pp cipher_text
altered_cipher_text = cipher_text[0..(prefix_length + chosen_clear_text.length - 2 * block_size - 1)] + (cipher_text[injection_range] ^ xor_mask) + cipher_text[(prefix_length + chosen_clear_text.length - block_size)..-1]
print "altered cipher text:"
pp altered_cipher_text
admin = cryptor.decrypt_and_check_admin(altered_cipher_text)
puts "admin: #{admin}"
