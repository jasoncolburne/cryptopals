#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'

p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17

message = <<EOT
For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
EOT
r = 548099063082341131477253921760299949438196259240
s = 857042759984254168557880549501802188789837994940

Cryptography = Jason::Math::Cryptography
NumberTheory = Jason::Math::NumberTheory
dsa = Cryptography::AsymmetricKey::DigitalSignatureAlgorithm.new(:sha_1, :'1024', p, q, g, nil, y)
sha = Cryptography::Digest::SecureHashAlgorithm.new(:'1')

raise 'could not verify signature' unless dsa.verify(message, r, s)
puts 'verified signature'

m = sha.digest(message).byte_string_to_integer
x = nil
(2..(2**16 - 1)).each do |k|
  x = ((s * k - m) * r.modular_inverse(q)) % q

  r_k = NumberTheory.modular_exponentiation(g, k, p) % q
  s_k = (NumberTheory.modular_inverse(k, q) * (m + x * r_k)) % q

  break if r == r_k && s == s_k
  x = nil
end

raise 'could not recover key' if x.nil?

puts "recovered key: #{x}"
puts 'sha1 fingerprint: ' + sha.digest(x.to_s(16)).byte_string_to_hex
