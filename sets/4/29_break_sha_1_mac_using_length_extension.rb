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
    @key = SecureRandom.random_bytes(16)
  end

  def terrible_mac(message)
    @digest.digest(@key + message)
  end

  def validate_mac(message, mac)
    @digest.digest(@key + message) == mac
  end
end

mac_daddy = MacDaddy.new(:sha_1)

message = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
mac = mac_daddy.terrible_mac(message)
raise 'Cannot validate mac' unless mac_daddy.validate_mac(message, mac)

puts 'unextended mac is validated'
puts 'forging new message/mac pair'

digest = Jason::Math::Cryptography::Digest.new(:sha_1)
digest.state = mac.unpack('N*')

injected_message = ';admin=true'
padded_message = Jason::Math::Cryptography::Digest.merkle_damgard_pad('x' * 16 + message)
forged_message = padded_message[16..] + injected_message
digest.cumulative_length = padded_message.length
forged_mac = digest.digest(injected_message)

raise 'forged mac was not validated' unless mac_daddy.validate_mac(forged_message, forged_mac)

puts 'successfully forged'
