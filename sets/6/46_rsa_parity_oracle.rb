#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'base64'

class RSAParityOracle
  def initialize(mode)
    @rsa = Jason::Math::Cryptography::AsymmetricKey::RivestShamirAdleman.new(mode)
    @n, d, @e = @rsa.generate_keypair!
  end

  def parity(cipher_text)
    (@rsa.decrypt(cipher_text) % 2).zero?
  end

  def encrypt(clear_text)
    cipher_text = @rsa.encrypt(clear_text)
    [cipher_text, @e, @n]
  end
end

mode = ARGV[0].to_sym
base64_clear_text = 'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='
clear_text = Base64.decode64(base64_clear_text)

oracle = RSAParityOracle.new(mode)
cipher_text, e, n = oracle.encrypt(clear_text.byte_string_to_integer)

# the last byte being incorrect really confused me
# so i found this: https://github.com/akalin/cryptopals-python3/blob/master/challenge46.py
upper = 1
lower = 0
denominator = 1
(n.to_byte_string.length * 8).times do
  cipher_text *= 2.modular_exponentiation(e, n)
  cipher_text %= n

  delta = upper - lower

  upper *= 2
  lower *= 2
  denominator *= 2

  if oracle.parity(cipher_text)
    upper -= delta
  else
    lower += delta
  end

  pp (n * upper / denominator).to_byte_string
end
