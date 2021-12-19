#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'

prng = Jason::Math::Cryptography::MersenneTwister19937.new(:mt19937)
10.times do
  p prng.extract_number
end
