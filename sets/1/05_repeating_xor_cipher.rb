#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'

puts Jason::Math::Cryptography.xor_cipher(ARGV[0], ARGV[1]).byte_string_to_hex
