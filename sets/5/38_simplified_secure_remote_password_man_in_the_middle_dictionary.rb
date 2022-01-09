#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'

$VERBOSE = nil

Cryptography = Jason::Math::Cryptography

# agreed
N = Cryptography::KeyAgreement::DiffieHellman::PARAMETERS[:'3072'][:p].to_i(16)
g = 2
I = 'address@domain.org'
P = 'password'
DICTIONARY = %w[badpassword, wrongpassword, incorrectpassword, falsepassword, otherpassword, password].shuffle.freeze

# server precomputes at signup (discarding x)
salt = SecureRandom.random_bytes(16)
sha = Cryptography::Digest::SecureHashAlgorithm.new(:'3_256')
x = sha.digest(salt + P).byte_string_to_integer
v = g.modular_exponentiation(x, N)

# client
a = SecureRandom.random_bytes(32).byte_string_to_integer % N
A = g.modular_exponentiation(a, N)

# server
b = SecureRandom.random_bytes(32).byte_string_to_integer % N
B = g.modular_exponentiation(b, N)

# spy
a_m = SecureRandom.random_bytes(32).byte_string_to_integer % N
A_m = g.modular_exponentiation(a_m, N)
b_m = SecureRandom.random_bytes(32).byte_string_to_integer % N
B_m = g.modular_exponentiation(b_m, N)
salt_m = SecureRandom.random_bytes(16)

# client ---I,A--> spy
# spy ---I,A_m--> server
# server ---salt,B--> spy
# spy ---salt_m,B_m--> client

# all
hmac = Cryptography::MessageAuthentication::HashedMessageAuthenticationCode.new(:sha_3_256, salt)

# client/spy
u_a = sha.digest(A.to_byte_string + B_m.to_byte_string).byte_string_to_integer

# server/spy
u_b = sha.digest(A_m.to_byte_string + B.to_byte_string).byte_string_to_integer

# client
x = sha.digest(salt_m + P).byte_string_to_integer
S = B_m.modular_exponentiation(a + u_a * x, N)
Kc = sha.digest(S.to_byte_string)
tag = hmac.tag(Kc)

# server
S = (A_m * v.modular_exponentiation(u_b, N)).modular_exponentiation(b, N)
Ks = sha.digest(S.to_byte_string)
valid_tag = hmac.tag(Ks)

# client ---tag--> spy

# spy
broken_password = nil
DICTIONARY.each do |word|
  x = sha.digest(salt_m + word).byte_string_to_integer
  v_k = g.modular_exponentiation(x, N)
  S = (A * v_k.modular_exponentiation(u_a, N)).modular_exponentiation(b_m, N)
  Kma = sha.digest(S.to_byte_string)
  broken_tag = hmac.tag(Kma)
  if Cryptography.secure_compare(broken_tag, tag)
    broken_password = word
    break
  end
end

raise 'could not crack password' if broken_password.nil?
puts 'successfully found password!'

x = sha.digest(salt + broken_password).byte_string_to_integer
S = B.modular_exponentiation(a_m + u_b * x, N)
Kmb = sha.digest(S.to_byte_string)
found_tag = hmac.tag(Kmb)

raise 'could not validate password!' unless Cryptography.secure_compare(found_tag, valid_tag)
puts 'password validated (man in the middle)'
