#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'

$VERBOSE = nil

Cryptography = Jason::Math::Cryptography

# agreed
N = Cryptography::KeyAgreement::DiffieHellman::PARAMETERS[:'3072'][:p].to_i(16)
g = 2
k = 3
I = 'address@domain.org'
P = 'password'

# server precomputes (discarding x)
salt = SecureRandom.random_bytes(16)
sha = Cryptography::Digest::SecureHashAlgorithm.new(:'3_256')
x = sha.digest(salt + P).byte_string_to_integer
v = g.modular_exponentiation(x, N)

# client
A = 0

# server
b = SecureRandom.random_bytes(32).byte_string_to_integer % N
B = (k * v + g.modular_exponentiation(b, N)) % N

hmac = Cryptography::MessageAuthentication::HashedMessageAuthenticationCode.new(:sha_3_256, salt)

# client
Kc = sha.digest(0.to_byte_string)

# server
u = sha.digest(A.to_byte_string + B.to_byte_string).byte_string_to_integer
S = (A * v.modular_exponentiation(u, N)).modular_exponentiation(b, N)
Ks = sha.digest(S.to_byte_string)

tag = hmac.tag(Kc)
valid_tag = hmac.tag(Ks)

raise 'could not validate password' unless Cryptography.secure_compare(tag, valid_tag)
puts 'password validated (null A)' 
