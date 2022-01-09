#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'

$VERBOSE = nil

Cryptography = Jason::Math::Cryptography

@sha = Cryptography::Digest::SecureHashAlgorithm.new(:'3_256')
def derive_key_and_iv(secret)
  digest = @sha.digest(secret.to_byte_string)
  key_range = 0..15
  iv_range = 16..27
  [digest[key_range], digest[iv_range] + "\x00" * 4]
end

puts "performing g = 1 attack on A and B..."

g = 1
dh_a = Cryptography::KeyAgreement::DiffieHellman.new(:'3072', nil, g)
dh_b = Cryptography::KeyAgreement::DiffieHellman.new(:'3072', nil, g)

a, A = dh_a.generate_pair
b, B = dh_b.generate_pair

puts "a: #{a}"
puts "A: #{A}"
puts "b: #{b}"
puts "B: #{B}"

a_secret = dh_a.compute_secret(a, B)
puts "compute_secret(a, M): #{a_secret}"
b_secret = dh_b.compute_secret(b, A)
puts "compute_secret(b, M): #{b_secret}"

raise "secrets weren't equal!" unless a_secret == b_secret

a_key, a_iv = derive_key_and_iv(a_secret)
b_key, b_iv = derive_key_and_iv(b_secret)

m_key, m_iv = derive_key_and_iv(1)

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

g = dh_a.p
dh_a = Cryptography::KeyAgreement::DiffieHellman.new(:'3072', nil, g)
dh_b = Cryptography::KeyAgreement::DiffieHellman.new(:'3072', nil, g)

a, A = dh_a.generate_pair
b, B = dh_b.generate_pair

puts "a: #{a}"
puts "A: #{A}"
puts "b: #{b}"
puts "B: #{B}"

a_secret = dh_a.compute_secret(a, B)
puts "compute_secret(a, M): #{a_secret}"
b_secret = dh_b.compute_secret(b, A)
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

g = dh_a.p - 1
dh_a = Cryptography::KeyAgreement::DiffieHellman.new(:'3072', nil, g)
dh_b = Cryptography::KeyAgreement::DiffieHellman.new(:'3072', nil, g)

a, A = dh_a.generate_pair
b, B = dh_b.generate_pair

puts "a: #{a}"
puts "A: #{A}"
puts "b: #{b}"
puts "B: #{B}"

a_secret = dh_a.compute_secret(a, B)
puts "compute_secret(a, M): #{a_secret}"
b_secret = dh_b.compute_secret(b, A)
puts "compute_secret(b, M): #{b_secret}"

raise "secrets weren't equal!" unless a_secret == b_secret

a_key, a_iv = derive_key_and_iv(a_secret)
b_key, b_iv = derive_key_and_iv(b_secret)

m1_key, m1_iv = derive_key_and_iv(1)
mpm1_key, mpm1_iv = derive_key_and_iv(g)

aes_a = Cryptography::SymmetricKey::AdvancedEncryptionStandard.new(:gcm_128, a_key)
aes_a.initialization_vector = a_iv
aes_b = Cryptography::SymmetricKey::AdvancedEncryptionStandard.new(:gcm_128, b_key)
aes_b.initialization_vector = b_iv
aes_m1 = Cryptography::SymmetricKey::AdvancedEncryptionStandard.new(:gcm_128, m1_key)
aes_m1.initialization_vector = m1_iv
aes_mpm1 = Cryptography::SymmetricKey::AdvancedEncryptionStandard.new(:gcm_128, mpm1_key)
aes_mpm1.initialization_vector = mpm1_iv

message_from_a = "hello, i am A."
cipher_text_from_a, tag_from_a = aes_a.encrypt(message_from_a, '')
puts "A sent: #{message_from_a}"

begin
  # i think this happens 3/4 times, so we'll do it first. gcm made this easier
  # but i do have a language detection module in my library
  clear_text_from_a_by_m = aes_m1.decrypt(cipher_text_from_a, '', tag_from_a)
  puts 'secret was 1'
  aes_m = aes_m1
rescue RuntimeError
  clear_text_from_a_by_m = aes_mpm1.decrypt(cipher_text_from_a, '', tag_from_a)
  puts 'secret was p - 1'
  aes_m = aes_mpm1
end

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
