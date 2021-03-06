#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'

puts "Sleeping for a random length of time, creating a MersenneTwister19937 prng and sleeping for more time..."
sleep(SecureRandom.random_number(150) + 50)
prng = Jason::Math::Cryptography::PseudoRandomNumberGeneration::MersenneTwister19937.new(:mt19937, Time.now.to_i)
sleep(SecureRandom.random_number(150) + 50)
target = prng.extract_number

puts "target value: #{target}"

imposter_prng = nil
first_number = nil
seed = Time.now.to_i

while first_number != target
  imposter_prng = Jason::Math::Cryptography::PseudoRandomNumberGeneration::MersenneTwister19937.new(:mt19937, seed)
  first_number = imposter_prng.extract_number
  seed -= 1
end

puts "found seed: #{seed + 1}"
puts

10.times do
  puts "prng output: #{prng.extract_number}"
  puts "imposter_prng output: #{imposter_prng.extract_number}"
end
