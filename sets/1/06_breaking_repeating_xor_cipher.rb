#!/usr/bin/env ruby

require 'base64'
require 'rubygems'
require 'bundler/setup'
require 'jason/math'

input = File.read(ARGV[0]).chomp.split("\n")
base64_data = input.join
data = Base64.strict_decode64(base64_data)

key = Jason::Math::Cryptography::ExclusiveOrCipher.break_repeated_key(data, 2..40)
puts Jason::Math::Cryptography::ExclusiveOrCipher.new(:repeated_key, key).decrypt(data)
