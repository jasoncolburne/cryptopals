#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'

text = ARGV[0]
block_size = ARGV[1].to_i
padded_text = Jason::Math::Cryptography::PKCS7.pad(text, block_size)
print "padded text: "
pp padded_text
padding = Jason::Math::Cryptography::PKCS7.validate(padded_text, block_size)
puts "padding: #{padding} (validated)"

modified_text = (text + ([padding + 1] * padding).pack('C*')).b
print "modified text: "
pp modified_text
begin
  Jason::Math::Cryptography::PKCS7.validate(modified_text, block_size)
rescue => e
  puts e
end

modified_text = (text + (1..padding).to_a.pack('C*')).b
print "modified text: "
pp modified_text
begin
  Jason::Math::Cryptography::PKCS7.validate(modified_text, block_size)
rescue => e
  puts e
end
