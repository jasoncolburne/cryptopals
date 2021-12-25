#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'rest_client'

url = 'localhost:4567/test'
file_path = './32_message.txt'
limit = ARGV.count.positive? ? ARGV.first.to_i : 10
existing_signature = ARGV.count >= 2 ? ARGV[1].hex_to_byte_string : ''
offset = existing_signature.length
signature = existing_signature.ljust(20, "\x00")
last_outer_time = 0

puts "attempting timing leak break using sample size of #{limit} rounds"
unless existing_signature.empty?
  puts "resuming previous session..."
  print existing_signature.byte_string_to_hex
end
(offset..19).each do |i|
  y = Time.now

  times = (0..255).map do |n|
    signature[i] = n.chr
    (0..(limit - 1)).map do
      x = Time.now

      begin
        RestClient.post(url, file: File.new(file_path), signature: signature.byte_string_to_hex)
      rescue RestClient::InternalServerError # rubocop:disable Lint/SuppressedException
      end

      Time.now - x
    end.sort[1..(limit - 2)].sum # drop highest and lowest value. would be nicer to statistically eliminate all outliers
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
puts RestClient.post(url, file: File.new(file_path), signature: signature.byte_string_to_hex)
