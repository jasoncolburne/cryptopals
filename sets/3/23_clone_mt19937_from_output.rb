#!/usr/bin/env ruby

require 'set'
require 'rubygems'
require 'bundler/setup'
require 'jason/math'

prng = Jason::Math::Cryptography::MersenneTwister19937.new(:mt19937, SecureRandom.random_number(2**19937))
cloned_prng = Jason::Math::Cryptography::MersenneTwister19937.new(:mt19937)
state_length = Jason::Math::Cryptography::MersenneTwister19937::PARAMETERS[:mt19937][:n]

SecureRandom.random_number(state_length).times do
  prng.extract_number
end

extracted_values = (0..(state_length - 1)).map { prng.extract_number }
untempered_values = extracted_values.map { |value| Jason::Math::Cryptography::MersenneTwister19937.untemper(value) }
cloned_prng.splice_state(untempered_values)

10.times do
  puts "prng: #{prng.extract_number}"
  puts "cloned_prng: #{cloned_prng.extract_number}"
end
