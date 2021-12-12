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
$random_prefix = SecureRandom.random_bytes(SecureRandom.random_number(15) + 17)

def encrypt(plain_text)
  algorithm = :aes_128_ecb
  cipher = Jason::Math::Cryptography::Cipher.new(algorithm, $key)
  message = $random_prefix + plain_text + $secret_string
  cipher.encrypt(message)
end

def detect_block_size(max_block_size = 64)
  current_length = encrypt("A".b).length
  
  (2..(max_block_size + 1)).each do |i|
    previous_length = current_length
    current_length = encrypt("A".b * i).length
    return current_length - previous_length if current_length != previous_length
  end

  nil
end

def split_blocks(data, block_size)
  block_count = data.length / block_size
  (0..(block_count - 1)).map do |i|
    data[(i * block_size)..((i + 1) * block_size - 1)]
  end
end

def determine_combined_length(block_size)
  current_length = encrypt("").size
  (1..(block_size - 1)).each do |i|
    previous_length = current_length
    current_length = encrypt("A".b * i).size
    return previous_length - i if current_length != previous_length
  end
end

def determine_prefix_length(block_size)
  current_blocks = split_blocks(encrypt(""), block_size)
  first_difference = nil
  (1..block_size).each do |i|
    previous_blocks = current_blocks
    current_blocks = split_blocks(encrypt("A".b * i), block_size)
    changed = false
    previous_blocks.each_with_index do |block, index|
      if block != current_blocks[index]
        if first_difference.nil?
          first_difference = index
        elsif first_difference != index
          changed = true
        end

        break
      end
    end

    return first_difference * block_size + (1 - i) % block_size if changed
  end
end

block_size = detect_block_size(64)
puts "block size: #{block_size}"
puts "ecb? #{Jason::Math::Cryptography::Cipher.detect_ecb?(encrypt("A".b * 48))}"

combined_length = determine_combined_length(block_size)
prefix_length = determine_prefix_length(block_size)
secret_length = combined_length - prefix_length

secret_string = ""
secret_length.times do |i|
  base_clear_text = "A".b * ((-secret_string.length - prefix_length - 1) % block_size)
  length = prefix_length + base_clear_text.length + secret_string.length
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
