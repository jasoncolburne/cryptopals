#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'rest_client'

url = 'localhost:4567/test'
signature = "\x00" * 20
file_path = './32_message.txt'
limit = ARGV.first.to_i
last_outer_time = 0

(0..19).each do |i|
  y = Time.now

  times = (0..255).map do |n|
    signature[i] = n.chr
    x = Time.now
    begin
      RestClient.post(url, file: File.new('./31_message.txt'), signature: signature.byte_string_to_hex)
    rescue RestClient::InternalServerError # rubocop:disable Lint/SuppressedException
    end
    Time.now - x
  end

  this_outer_time = Time.now - y

  if (this_outer_time - last_outer_time).abs < 1.0
    puts
    raise 'No significant difference in outer loop execution time between rounds - attack is failing.'
  end

  last_outer_time = this_outer_time

  char = times.index(times.max).chr
  print char.byte_string_to_hex
  signature[i] = char
end

puts
puts RestClient.post(url, file: File.new('./31_message.txt'), signature: signature.byte_string_to_hex)
