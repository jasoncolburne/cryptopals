#!/usr/bin/env ruby

require 'base64'
require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'securerandom'
require 'cgi'

class MacDaddy
  def initialize(algorithm)
    @digest = Jason::Math::Cryptography::Digest.new(algorithm)
  end

  def terrible_mac(key, message)
    @digest.digest(key + message)
  end
end

mac_daddy = MacDaddy.new(:sha_1)

key = SecureRandom.random_bytes(16)
message = 'Our little secret'
mac = mac_daddy.terrible_mac(key, message)

altered_message = 'P' + message[1..]
altered_mac = mac_daddy.terrible_mac(key, altered_message)
raise "Macs match! The chances of this happening are astronomically small." if mac == altered_mac
puts "Macs differ when message is altered."

altered_key = (key.b[0] ^ "\x01") + key[1..]
altered_mac = mac_daddy.terrible_mac(altered_key, message)
raise "Macs match! The chances of this happening are astronomically small." if mac == altered_mac
puts "Macs differ when key is altered."
