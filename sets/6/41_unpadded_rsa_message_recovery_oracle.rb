#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'set'

class UnpaddedRSADecryptionOracle
  def initialize(mode)
    @rsa = Jason::Math::Cryptography::AsymmetricKey::RivestShamirAdleman.new(mode)
    @sha = Jason::Math::Cryptography::Digest::SecureHashAlgorithm.new(:'3_224')
    @n, _, @e = @rsa.generate_keypair!
    @seen = Set[]
  end

  def decrypt(cipher_text)
    digest = @sha.digest(cipher_text.to_byte_string)
    raise 'cannot decrypt twice' if @seen.include?(digest)
    @seen << digest

    @rsa.decrypt(cipher_text)
  end

  def encrypt(clear_text)
    cipher_text = @rsa.encrypt(clear_text)
    [cipher_text, @e, @n]
  end
end

mode = ARGV[0].to_sym
clear_text = ARGV[1].byte_string_to_integer

oracle = UnpaddedRSADecryptionOracle.new(mode)
puts 'encrypting...'
cipher_text, e, n = oracle.encrypt(clear_text)
puts "cipher_text: #{cipher_text}"
puts "e: #{e}"
puts "n: #{n}"

puts 'decrypting once...'
decrypted_text = oracle.decrypt(cipher_text)
puts "decrypted: #{decrypted_text.to_byte_string}"

puts 'verifying oracle will not decrypt again...'
begin
  oracle.decrypt(cipher_text)
  raise 'oracle decrypted twice. failure.'
rescue RuntimeError
  puts 'verified.'
end

s = nil
loop do
  s = SecureRandom.random_bytes(1920).byte_string_to_integer % n
  break unless s < 2
end

puts "sending altered cipher text to oracle..."
bogus_cipher_text = (s.modular_exponentiation(e, n) * cipher_text) % n
bogus_clear_text = oracle.decrypt(bogus_cipher_text)

recovered_text = (bogus_clear_text * s.modular_inverse(n)) % n
puts "recovered: #{recovered_text.to_byte_string}"
