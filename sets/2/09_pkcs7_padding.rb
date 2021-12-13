#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'

pp Jason::Math::Cryptography::PKCS7.pad(ARGV[0], ARGV[1].to_i)
