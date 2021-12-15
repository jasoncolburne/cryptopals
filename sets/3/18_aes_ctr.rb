#!/usr/bin/env ruby

require 'set'
require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'securerandom'

cipher_text = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".base64_to_byte_string

key = "YELLOW SUBMARINE"
nonce = "\x00" * 8

cipher = Jason::Math::Cryptography::Cipher.new(:aes_128_ctr, key)
puts cipher.decrypt(cipher_text, nonce)
