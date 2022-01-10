#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'

message = ARGV[1].byte_string_to_integer
rsa = Jason::Math::Cryptography::AsymmetricKey::RivestShamirAdleman.new(ARGV[0].to_sym, nil, nil, 3)

mapping = 3.times.map do |i|
  puts "generating keypair #{i}..."
  n, _, _ = rsa.generate_keypair!
  [n, rsa.encrypt(message)]
end.to_h

remainder = mapping.chinese_remainder_theorem(enforce_co_primality: false)
puts "recovered: #{remainder.root(3).to_byte_string}"
