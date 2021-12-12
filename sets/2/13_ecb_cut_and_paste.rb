#!/usr/bin/env ruby

require 'base64'
require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'securerandom'

$key = SecureRandom.random_bytes(16)

def encrypt(clear_text)
  algorithm = :aes_128_ecb
  cipher = Jason::Math::Cryptography::Cipher.new(algorithm, $key)
  cipher.encrypt(clear_text)
end

def decrypt(cipher_text)
  algorithm = :aes_128_ecb
  cipher = Jason::Math::Cryptography::Cipher.new(algorithm, $key)
  cipher.decrypt(cipher_text)
end

def profile_for(email)
  raise "Cannot encode & or =" if email.count('&=') > 0

  {
    email: email,
    uid: SecureRandom.random_number(90) + 10,
    role: 'user',
  }.map { |key, value| "#{key}=#{value}" }.join("&")  
end

def parse_profile(profile_string)
  profile_string.split('&').map { |pair| pair.split('=') }.to_h
end

minimum_name = 'w@example.com'
minimum_length = profile_for(minimum_name).length
attack_name_length = 5 - minimum_length % 16

first_name = 'wardenbonusclonejar'[0..(attack_name_length - 1)]
email = "#{first_name}@example.com"
profile_string = profile_for(email)

cipher_text = encrypt(profile_string)

block_count = cipher_text.length / 16
blocks = (0..(block_count - 1)).map do |i|
  cipher_text[(i * 16)..((i + 1) * 16 - 1)]
end

chosen_clear_text = "admin"
altered_block = encrypt("admin")
pp blocks
blocks.pop
blocks << altered_block
pp blocks
altered_cipher_text = blocks.join

clear_text = decrypt(altered_cipher_text)
pp parse_profile(clear_text)
