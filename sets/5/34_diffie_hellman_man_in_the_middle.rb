#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'

Cryptography = Jason::Math::Cryptography

@sha = Cryptography::Digest::SecureHashAlgorithm.new(:'3_256')
def derive_key_and_iv(secret)
  digest = @sha.digest(secret.to_byte_string)
  key_range = 0..15
  iv_range = 16..27
  [digest[key_range], digest[iv_range] + "\x00" * 4]
end

puts "performing generic mitm attack on A and B..."

dh = Cryptography::KeyAgreement::DiffieHellman.new(:'3072')

a, A = dh.generate_pair
b, B = dh.generate_pair
m, M = dh.generate_pair

puts "a: #{a}"
puts "A: #{A}"
puts "b: #{b}"
puts "B: #{B}"
puts "m: #{m}"
puts "M: #{M}"

ma_secret = dh.compute_secret(a, M)
puts "compute_secret(a, M): #{ma_secret}"
mb_secret = dh.compute_secret(b, M)
puts "compute_secret(b, M): #{mb_secret}"

secret = dh.compute_secret(m, A)
raise 'secrets do not match!' unless secret == ma_secret
secret = dh.compute_secret(m, B)
raise 'secrets do not match!' unless secret == mb_secret

ma_key, ma_iv = derive_key_and_iv(ma_secret)
mb_key, mb_iv = derive_key_and_iv(mb_secret)

aes_a = Cryptography::SymmetricKey::AdvancedEncryptionStandard.new(:gcm_128, ma_key)
aes_a.initialization_vector = ma_iv
aes_ma = Cryptography::SymmetricKey::AdvancedEncryptionStandard.new(:gcm_128, ma_key)
aes_ma.initialization_vector = ma_iv

aes_b = Cryptography::SymmetricKey::AdvancedEncryptionStandard.new(:gcm_128, mb_key)
aes_b.initialization_vector = mb_iv
aes_mb = Cryptography::SymmetricKey::AdvancedEncryptionStandard.new(:gcm_128, mb_key)
aes_mb.initialization_vector = mb_iv

message_from_a = "hello, i am A."
cipher_text_from_a, tag_from_a = aes_a.encrypt(message_from_a, '')
puts "A sent: #{message_from_a}"
clear_text_from_a = aes_ma.decrypt(cipher_text_from_a, '', tag_from_a)
puts "M saw: #{clear_text_from_a}"
cipher_text_from_m_to_b, tag_from_m_to_b = aes_mb.encrypt(clear_text_from_a, '')
clear_text_from_m_to_b = aes_b.decrypt(cipher_text_from_m_to_b, '', tag_from_m_to_b)
puts "B received: #{clear_text_from_m_to_b}"
response_from_b = "hi A! i am B."
cipher_text_from_b, tag_from_b = aes_b.encrypt(response_from_b, '')
puts "B sent: #{response_from_b}"
clear_text_from_b = aes_mb.decrypt(cipher_text_from_b, '', tag_from_b)
puts "M saw: #{clear_text_from_b}"
cipher_text_from_m_to_a, tag_from_m_to_a = aes_ma.encrypt(clear_text_from_b, '')
clear_text_from_m_to_a = aes_a.decrypt(cipher_text_from_m_to_a, '', tag_from_m_to_a)
puts "A received: #{clear_text_from_m_to_a}"

puts 'performing parameter injection attack on A and B'

P = dh.p
puts "P: #{P}"

a_secret = dh.compute_secret(a, P)
puts "compute_secret(a, M): #{a_secret}"
b_secret = dh.compute_secret(b, P)
puts "compute_secret(b, M): #{b_secret}"

raise "secrets weren't equal!" unless a_secret == b_secret

a_key, a_iv = derive_key_and_iv(a_secret)
b_key, b_iv = derive_key_and_iv(b_secret)

m_key, m_iv = derive_key_and_iv(0)

aes_a = Cryptography::SymmetricKey::AdvancedEncryptionStandard.new(:gcm_128, a_key)
aes_a.initialization_vector = a_iv
aes_b = Cryptography::SymmetricKey::AdvancedEncryptionStandard.new(:gcm_128, b_key)
aes_b.initialization_vector = b_iv
aes_m = Cryptography::SymmetricKey::AdvancedEncryptionStandard.new(:gcm_128, m_key)
aes_m.initialization_vector = m_iv

message_from_a = "hello, i am A."
cipher_text_from_a, tag_from_a = aes_a.encrypt(message_from_a, '')
puts "A sent: #{message_from_a}"
clear_text_from_a_by_m = aes_m.decrypt(cipher_text_from_a, '', tag_from_a)
puts "M saw: #{clear_text_from_a_by_m}"
clear_text_from_a = aes_b.decrypt(cipher_text_from_a, '', tag_from_a)
puts "B received: #{clear_text_from_a}"

response_from_b = "hi A! i am B."
cipher_text_from_b, tag_from_b = aes_b.encrypt(response_from_b, '')
puts "B sent: #{response_from_b}"
clear_text_from_b_by_m = aes_m.decrypt(cipher_text_from_b, '', tag_from_b)
puts "M saw: #{clear_text_from_b_by_m}"
clear_text_from_b = aes_a.decrypt(cipher_text_from_b, '', tag_from_b)
puts "A received: #{clear_text_from_b}"
