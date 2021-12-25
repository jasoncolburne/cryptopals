#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'rest_client'

url = 'localhost:4567/test'

signature = "\x00" * 20

(0..19).each do |i|
  times = (0..255).map do |n|
    signature[i] = n.chr
    x = Time.now
    begin
      RestClient.post(url, file: File.new('./31_message.txt'), signature: signature.byte_string_to_hex)
    rescue
    end
    Time.now - x
  end

  signature[i] = times.index(times.max).chr
end

p signature.byte_string_to_hex
