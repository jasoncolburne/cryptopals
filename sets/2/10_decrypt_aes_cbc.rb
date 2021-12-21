#!/usr/bin/env ruby

require 'base64'
require 'rubygems'
require 'bundler/setup'
require 'jason/math'

cipher_text = Base64.decode64(File.read(ARGV[0]))

cipher = Jason::Math::Cryptography::Cipher.new(:aes_128_cbc, ARGV[1])
cipher.initialization_vector = "\x00".b * 16
puts cipher.decrypt(cipher_text)
