#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'

rsa = Jason::Math::Cryptography::AsymmetricKey::RivestShamirAdleman.new(:'3072', nil, nil, 3)
_, _, n = rsa.generate_keypair!

raise 'could not decrypt 42 after encryption' unless 42 == rsa.decrypt(rsa.encrypt(42))

10.times do
  number = SecureRandom.random_bytes(384).byte_string_to_integer % n
  raise 'could not decrypt big number after encryption' unless number == rsa.decrypt(rsa.encrypt(number))
end

puts 'success!'
