#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'

message = ARGV[1].byte_string_to_integer
rsa = Jason::Math::Cryptography::AsymmetricKey::RivestShamirAdleman.new(ARGV[0].to_sym, nil, nil, 3)

puts 'generating keypair a...'
na, _, _ = rsa.generate_keypair!
cipher_text_a = rsa.encrypt(message)
puts 'generating keypair b...'
nb, _, _ = rsa.generate_keypair!
cipher_text_b = rsa.encrypt(message)
puts 'generating keypair c...'
nc, _, _ = rsa.generate_keypair!
cipher_text_c = rsa.encrypt(message)

mapping = {
  na => cipher_text_a,
  nb => cipher_text_b,
  nc => cipher_text_c
}

remainder = mapping.chinese_remainder_theorem(enforce_co_primality: false)
puts "recovered: #{remainder.root(3).to_byte_string}"
