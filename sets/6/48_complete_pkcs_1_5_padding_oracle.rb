#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'

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
    raise "clear text too large to encrypt" if clear_text.length > @key_length

    cipher_text = @rsa.encrypt(clear_text.byte_string_to_integer)
    [cipher_text, @e, @n]
  end
end

mode = ARGV[0].to_sym
clear_text = ARGV[1]
puts 'generating keys...'
oracle = PKCSPaddingOracle.new(mode)
puts 'encrypting message without padding...'
c, e, n = oracle.encrypt(clear_text)
raise 'encrypted text is pkcs conformant' if oracle.valid?(c)
puts 'produced a non-conformant cipher_text to recover'

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

k = n.to_byte_string.length
B = 2**(8 * (k - 2))

M_ = [[(2 * B), (3 * B - 1)]]

# blinding

puts 'blinding...'
s0 = c0 = nil
loop do
  s0 = SecureRandom.random_number(1..(n-1))
  c0 = (c * s0.modular_exponentiation(e, n)) % n
  break if oracle.valid?(c0)
end
puts "found s0: #{s0}"
puts "found c0: #{c0}"

s_ = s0

# iteration 1
s = ceiling(n, 3 * B)
puts "finding a valid s value beginning at #{s}..."
loop do
  s += 1 
  print "\e[0Gtrying s: #{s}"
  c = (c0 * s.modular_exponentiation(e, n)) % n
  break if oracle.valid?(c)
end

puts
M = construct_M(M_, s, B, n)

while M.count > 1 || M[0][0] != M[0][1]
  print "\e[0Gintervals remaining: #{M.count}"

  M_ = M
  s_ = s

  if M.count == 1
    a, b = M[0]
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
        found = true if oracle.valid?((c0 * s.modular_exponentiation(e, n)) % n)
        break if found
        s += 1
      end

      break if found
      r += 1
    end
  else
    s = s_ + 1
    s += 1 until oracle.valid?((c0 * s.modular_exponentiation(e, n)) % n)
  end

  M = construct_M(M_, s, B, n)
end

puts
recovered_text = (M[0][0] * s0.modular_inverse(n)) % n
puts "recovered: #{recovered_text.to_byte_string}"
