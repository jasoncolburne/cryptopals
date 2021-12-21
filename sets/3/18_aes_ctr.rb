#!/usr/bin/env ruby

require 'set'
require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'securerandom'

cipher_text = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".base64_to_byte_string

key = "YELLOW SUBMARINE"
nonce = "\x00" * 8
cipher = Jason::Math::Cryptography::Cipher.new(:aes_128_ctr, key)

# this requires a non-standard mode so i'll do it manually by manipulating the iv
p (cipher_text.to_blocks(16).each_with_index.map do |block, counter|
  initialization_vector = nonce + [counter].pack('Q<*')
  cipher.initialization_vector = initialization_vector
  cipher.decrypt(block)
end.to_a.join)
