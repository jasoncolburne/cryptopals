#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'

dh = Jason::Math::Cryptography::KeyAgreement::DiffieHellman.new(:'1536')

a, A = dh.generate_pair
b, B = dh.generate_pair

puts "a: #{a}"
puts "A: #{A}"
puts "b: #{b}"
puts "B: #{B}"

secret = dh.compute_secret(a, B)
puts "compute_secret(a, B): #{secret}"
secret = dh.compute_secret(b, A)
puts "compute_secret(b, A): #{secret}"
