#!/usr/bin/env ruby

require 'base64'
require 'rubygems'
require 'bundler/setup'
require 'jason/math'

key = 'YELLOW SUBMARINE'
input = File.read(ARGV[0]).chomp.split("\n")
base64_data = input.join
cipher_text = Base64.strict_decode64(base64_data)

aes = Jason::Math::Cryptography::AdvancedEncryptionStandard.new(:ecb_128, key)
puts aes.decrypt(cipher_text)
