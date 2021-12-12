#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'

input = File.read(ARGV[0]).chomp.split("\n")

input.each do |hex_string|
  potential_cipher_text = hex_string.hex_to_byte_string
  puts hex_string if Jason::Math::Cryptography::Cipher.detect_ecb?(potential_cipher_text)
end
