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

# protocol

# client
a = SecureRandom.random_bytes(32).byte_string_to_integer % N
A = g.modular_exponentiation(a, N)

# client ---I,A--> server

# server
b = SecureRandom.random_bytes(32).byte_string_to_integer % N
B = (k * v + g.modular_exponentiation(b, N)) % N

# server ---salt,B--> client

# both
u = sha.digest(A.to_byte_string + B.to_byte_string).byte_string_to_integer

# client
# x = sha.digest(salt + P).byte_string_to_integer
S = (B - k * g.modular_exponentiation(x, N)).modular_exponentiation((a + u * x), N)
Kc = sha.digest(S.to_byte_string)

# server
S = (A * v.modular_exponentiation(u, N)).modular_exponentiation(b, N)
Ks = sha.digest(S.to_byte_string)

hmac = Cryptography::MessageAuthentication::HashedMessageAuthenticationCode.new(:sha_3_256, salt)
tag = hmac.tag(Kc)
valid_tag = hmac.tag(Ks)

# client ---tag--> server

raise 'server failed to validate request' unless Cryptography.secure_compare(tag, valid_tag)
puts 'password validated'
