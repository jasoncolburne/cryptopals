#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'

Cryptography = Jason::Math::Cryptography
RSA = Cryptography::AsymmetricKey::RivestShamirAdleman
SHA = Cryptography::Digest::SecureHashAlgorithm

mode = ARGV[0].to_sym
rsa = RSA.new(mode, nil, nil, 3)
@sha = SHA.new(:'1')
rsa.generate_keypair!

def pkcs1_pad(message, length)
  asn_bytes = "\xde\xad\xbe\xef".b
  message = message.to_byte_string.b
  
  raise 'not enough room to pad' unless message.length <= length - 28
  
  padding = "\x00\x01".b + ("\xff".b * (length - message.length - 27)) + "\x00".b
  message = message + padding + asn_bytes
  message += @sha.digest(message)
  message.byte_string_to_integer
end

def recover_clear_text_signature_and_verify_padding(rsa, signature)
  padded_clear_text = rsa.encrypt(signature).to_byte_string
  digest = padded_clear_text[-20..]
  asn_bytes = padded_clear_text[-24..-21]
  padded_clear_text = padded_clear_text[0..-25]

  reversed_padded_clear_text = padded_clear_text.reverse
  
  finish, start = (0...(padded_clear_text.length - 1)).find_all { |i| reversed_padded_clear_text[i] == "\x00" }.first(2).map { |i| padded_clear_text.length - i - 1 }
  padding = padded_clear_text[start..finish]
  raise 'incorrect padding' if start.nil? || finish.nil? || finish != padded_clear_text.length - 1
  raise 'incorrect padding' if padding !~ Regexp.new("\x00\x01\xff+\x00".b)
  raise 'incorrect padding' unless Cryptography.secure_compare(asn_bytes, "\xde\xad\xbe\xef")
  raise 'incorrect padding' unless Cryptography.secure_compare(digest, @sha.digest(padded_clear_text + asn_bytes))
  padded_clear_text[0..(start - 1)].byte_string_to_integer
end

def recover_clear_text_signature_and_strip_padding(rsa, signature)
  padded_clear_text = rsa.encrypt(signature).to_byte_string
  padding_start = padded_clear_text.index("\x00")
  padded_clear_text[0..(padding_start - 1)].byte_string_to_integer
end

message = pkcs1_pad('hi mom'.byte_string_to_integer, RSA::PARAMETERS[mode][:key_length] - 1)
valid_signature = rsa.decrypt(message)

clear_text = recover_clear_text_signature_and_verify_padding(rsa, valid_signature)
puts "recovered from valid signature, verifying padding: #{clear_text.to_byte_string}"
clear_text = recover_clear_text_signature_and_strip_padding(rsa, valid_signature)
puts "recovered from valid signature, stripping padding: #{clear_text.to_byte_string}"

bytes_to_pack = RSA::PARAMETERS[mode][:key_length] * 2 / 3 + 1
padded_suspicious_message = pkcs1_pad('hi eve'.byte_string_to_integer, RSA::PARAMETERS[mode][:key_length] - bytes_to_pack - 1)
forged_message = padded_suspicious_message.to_byte_string + "\x00".b * bytes_to_pack
forged_message = forged_message.byte_string_to_integer
delta = (forged_message.root(3) + 1)**3 - forged_message
forged_message = padded_suspicious_message.to_byte_string + delta.to_byte_string.rjust(bytes_to_pack, "\x00")
forged_message = forged_message.byte_string_to_integer

forged_signature = rsa.decrypt(forged_message)

begin
  clear_text = recover_clear_text_signature_and_verify_padding(rsa, forged_signature)
  raise 'verification of forged message succeeded (verification algorithm flawed)'
rescue RuntimeError
  puts 'forged signature detected by verification routine'
end

clear_text = recover_clear_text_signature_and_strip_padding(rsa, forged_signature)
puts "recovered from forged signature, stripping padding: #{clear_text.to_byte_string}"
