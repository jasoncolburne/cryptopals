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

$key = SecureRandom.random_bytes(16)
$secret_string = Base64.decode64(base64_string)

def encrypt(plain_text)
  algorithm = :aes_128_ecb
  cipher = Jason::Math::Cryptography::Cipher.new(algorithm, $key)
  message = plain_text + $secret_string
  cipher.encrypt(message)
end

def detect_block_size(max_block_size = 64)
  current_text = encrypt("A".b)
  
  (2..(max_block_size + 1)).each do |i|
    previous_text = current_text
    current_text = encrypt("A".b * i)
    return i - 1 if previous_text[0..3] == current_text[0..3]
  end

  nil
end

def determine_secret_length(block_size)
  current_length = encrypt("").size
  (1..(block_size - 1)).each do |i|
    previous_length = current_length
    current_length = encrypt("A".b * i).size
    return previous_length - i if current_length != previous_length
  end
end

block_size = detect_block_size(64)
puts "block size: #{block_size}"
puts "ecb? #{Jason::Math::Cryptography::Cipher.detect_ecb?(encrypt("A".b * 48))}"

secret_length = determine_secret_length(block_size)

secret_string = ""
secret_length.times do |i|
  base_clear_text = "A".b * ((-secret_string.length - 1) % block_size)
  length = base_clear_text.length + secret_string.length
  target = encrypt(base_clear_text)[0..length]

  (0..255).each do |n|
    char = n.chr
    potential_match = encrypt(base_clear_text + secret_string + char)[0..length]
    if potential_match == target
      print char
      secret_string << char
      break
    end
  end
end
