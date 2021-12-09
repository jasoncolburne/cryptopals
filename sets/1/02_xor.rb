#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'

puts (ARGV[0].hex_to_byte_string ^ ARGV[1].hex_to_byte_string).byte_string_to_hex
