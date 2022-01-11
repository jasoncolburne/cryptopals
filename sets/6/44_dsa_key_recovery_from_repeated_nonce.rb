#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'set'

lines = File.read(ARGV[0]).chomp.split("\n")

i = 0
signatures = []
while i < lines.length
  record = {}

  record[:msg] = lines[i].split(': ')[1]
  i += 1
  record[:s] = lines[i].split(': ')[1].to_i
  i += 1
  record[:r] = lines[i].split(': ')[1].to_i
  i += 1
  record[:m] = lines[i].split(': ')[1].to_i(16)
  i += 1

  signatures << record
end

# group by r so we find the reused k values, filter out single use values
grouped_signatures = signatures.group_by { |r| r[:r] }.select { |k, v| v.count > 1 }

p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821

Cryptography = Jason::Math::Cryptography
sha = Cryptography::Digest::SecureHashAlgorithm.new(:'1')
dsa = Cryptography::AsymmetricKey::DigitalSignatureAlgorithm.new(:sha_1, :'1024', p, q, g, nil, y)

signatures.each do |record|
  raise 'could not verify signature' unless dsa.verify(record[:msg], record[:r], record[:s])
end
puts 'signatures verified with public key'

x_values = Set[]
grouped_signatures.values.each do |records|
  a = records.first
  b = records.last

  m1 = a[:m]
  m2 = b[:m]
  s1 = a[:s]
  s2 = b[:s]
  r1 = a[:r]
  r2 = b[:r]

  ma = sha.digest(a[:msg]).byte_string_to_integer
  mb = sha.digest(b[:msg]).byte_string_to_integer

  k = ((m1 - m2) * (s1 - s2).modular_inverse(q)) % q
  x1 = ((s1 * k - ma) * r1.modular_inverse(q)) % q
  x2 = ((s2 * k - mb) * r2.modular_inverse(q)) % q

  raise 'computed inconsistent key values' unless x1 == x2

  x_values << x1
end

raise 'found more than one key' unless x_values.count == 1

x = x_values.first
puts "found key: #{x}"
puts "sha1 fingerprint: " + sha.digest(x.to_s(16)).byte_string_to_hex
