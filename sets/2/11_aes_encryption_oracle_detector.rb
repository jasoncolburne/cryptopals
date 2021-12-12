#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'securerandom'

def encryption_oracle(plain_text)
  algorithm = SecureRandom.random_number(2).zero? ? :aes_128_cbc : :aes_128_ecb
  cipher = Jason::Math::Cryptography::Cipher.new(algorithm, SecureRandom.random_bytes(16))
  prefix_length = SecureRandom.random_number(5) + 5
  suffix_length = SecureRandom.random_number(5) + 5
  message = SecureRandom.random_bytes(prefix_length)
  message << plain_text
  message << SecureRandom.random_bytes(suffix_length)
  cipher.encrypt(message, SecureRandom.random_bytes(16))
end

pp ((0..(ARGV[0].to_i - 1)).map do
  cipher_text = encryption_oracle("A" * 16 * 3) # 3 blocks will yield a dupe block
  Jason::Math::Cryptography::Cipher.detect_ecb?(cipher_text)
end)
