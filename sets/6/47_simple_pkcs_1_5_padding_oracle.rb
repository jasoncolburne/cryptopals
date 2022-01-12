#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'base64'

$VERBOSE = nil

class PKCSPaddingOracle
  def initialize(mode)
    @rsa = Jason::Math::Cryptography::AsymmetricKey::RivestShamirAdleman.new(mode)
    @n, _, @e = @rsa.generate_keypair!
    @key_length = @rsa.instance_variable_get(:@key_length)
  end

  # no early returns
  def valid?(cipher_text)
    clear_text = @rsa.decrypt(cipher_text).to_byte_string.rjust(@key_length, "\x00")
    
    valid = true
    valid &&= clear_text[0] == "\x00" && clear_text[1] == "\x02"
    valid &&= (2..9).none? { |i| clear_text[i].ord.zero? }
    valid && clear_text[10..].include?("\x00")
  end

  def encrypt(clear_text)
    raise "clear text too large to encrypt" if clear_text.length > @key_length - 11

    to_encrypt = "\x00\x02"
    bytes_to_add = @key_length - clear_text.length - 3
    bytes_to_add.times do
      to_encrypt << SecureRandom.random_number(1..255).chr
    end
    to_encrypt << "\x00" + clear_text

    cipher_text = @rsa.encrypt(to_encrypt.byte_string_to_integer)
    [cipher_text, @e, @n]
  end
end

mode = ARGV[0].to_sym
clear_text = 'kick it, CC'
puts 'generating keys...'
oracle = PKCSPaddingOracle.new(mode)
puts 'encrypting message...'
c, e, n = oracle.encrypt(clear_text)
raise 'encrypted text not pkcs conformant' unless oracle.valid?(c)
puts 'produced a valid cipher_text'

# computes the ceiling of a / b
def ceiling(a, b)
  (a + b - 1) / b
end

def construct_M(previous_M, s, theB, n)
  result = []

  previous_M.each do |range|
    a, b = range

    min = ceiling(a * s - 3 * B  + 1, n)
    max = (b * s - 2 * B) / n

    (min..max).each do |r|
      low = [a, ceiling(2 * theB + r * n, s)].max
      high = [b, (3 * theB - 1 + r * n) / s].min
      result << [low, high]
    end
  end

  result
end

# we have a ciphertext with valid padding to start with
s_ = 1
k = n.to_byte_string.length
B = 2**(8 * (k - 2))

M_ = [[(2 * B), (3 * B - 1)]]

puts 'finding a valid s value..'
# iteration 1
s = n / (3 * B)
puts "starting value: #{s}"
(s += 1; print '.') until oracle.valid?((c * s.modular_exponentiation(e, n)) % n)
puts
puts "found s: #{s}"
puts 'converging...'
M = construct_M(M_, s, B, n)

while M.count > 1 || M[0][0] != M[0][1]
  M_ = M
  s_ = s

  if M.count == 1
    a, b = M[0]
    puts b - a

    r = ceiling(2 * b * s_ - 4 * B, n)
    found = false
    loop do
      min = ceiling(2 * B + r * n, b)
      max = (3 * B + r * n - 1) / a # not positive about the -1 i threw in here
                                    # but i think it makes the strict greater than
                                    # work properly with the integer division

      s = min
      loop do
        break if s > max
        found = true if oracle.valid?((c * s.modular_exponentiation(e, n)) % n)
        break if found
        s += 1
      end

      break if found
      r += 1
    end

  else
    raise 'case not implemented'
  end

  M = construct_M(M_, s, B, n)
end

recovered_text = M[0][0].to_byte_string.rjust(k, "\x00")

# we won't bother writing a proper strip padding function for this
puts "recovered: #{recovered_text.split("\x00").last}"
