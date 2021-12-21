#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'

puts Jason::Math::Cryptography::Cipher.new(:xor_repeated_key, ARGV[1]).encrypt(ARGV[0]).byte_string_to_hex
