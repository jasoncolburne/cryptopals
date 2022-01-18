#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'set'

Cryptography = Jason::Math::Cryptography
AES = Cryptography::SymmetricKey::AdvancedEncryptionStandard
Blake = Cryptography::Digest::Blake
PKCS7 = Cryptography::PKCS7

module BrokenCBCImplementation
  def encrypt_cbc(clear_text)
    length = clear_text.length
    iterations = (length.to_f / @block_size).ceil
    cipher_text = ''.b

    iterations.times do |i|
      to_xor = clear_text[(i * @block_size)..[(i + 1) * @block_size - 1, length - 1].min]
      to_xor = to_xor.ljust(@block_size, "\x00")
      to_cipher = Jason::Math::Utility.xor(to_xor, @initialization_vector)
      @initialization_vector = cipher(to_cipher)
      cipher_text << @initialization_vector
    end

    cipher_text
  end
end

AES.prepend BrokenCBCImplementation

class MerkleDamgardConstructionHash
  def initialize
    @aes = AES.new(:cbc_128, "\x00" * 16)
    @blake = Blake.new(:'2b', 2, "\x00" * 32, )
  end
  
  def poor_digest(message, state = 0x01234567.to_byte_string)
    message = PKCS7.pad(message, 16) unless (message.length % 16).zero?

    Cryptography::Cipher.split_into_blocks(message, 16).each do |block|
      s1 = state[0..1]
      @aes.initialization_vector = s1.rjust(16, "\x00")
      s1 = @aes.encrypt(block)[0..1]

      s2 = state[2..3]
      h = @blake.instance_variable_get(:@h)
      h[0] ^= (s2.byte_string_to_integer << 8)
      @blake.state = h
      s2 = @blake.digest(block)

      state = s1 + s2
    end

    state
  end

  def poorer_digest(message, state = 0x0123.to_byte_string)
    message = PKCS7.pad(message, 16) unless (message.length % 16).zero?
    length = 2

    Cryptography::Cipher.split_into_blocks(message, 16).each do |block|
      @aes.initialization_vector = state.rjust(16, "\x00")
      state = @aes.encrypt(block)[0..(length - 1)]
    end

    state
  end
end

def collide_two(md, state = 0x0123.to_byte_string)
  inputs = Hash.new do |h, k|
    h[k] = []
  end
  
  i = 0
  loop do
    m = i.to_byte_string.rjust(16, "\x00")
    print "\e[0G#{m.byte_string_to_hex}"
    digest = md.poorer_digest(m, state)
    inputs[digest] << m
    return [digest, inputs[digest]] if inputs[digest].count > 1
    i += 1
  end
end

def collide(md, n)
  collisions = [{ 0x0123.to_byte_string => [''.b] }]
  generation = 0
  loop do
    next_generation = Hash.new do |h, k|
      h[k] = Set[]
    end
    collisions[generation].each_pair do |state, inputs|
      state, colliding_inputs = collide_two(md, state)
      inputs.each do |input|
        next_generation[state] |= colliding_inputs.map { |new_input| input + new_input }.to_set
      end
    end
    collisions << next_generation
    return collisions[1..] if collisions[1..].map(&:count).sum >= n
    generation += 1
  end
end

md = MerkleDamgardConstructionHash.new

puts 'finding collisions in weak hash function...'
collisions = collide(md, 5).inject(&:merge)
puts
puts "found #{collisions.count} digests with colliding inputs, #{collisions.values.map(&:count).sum} distinct inputs"

def collide_two_blake_composite(md, state = 0x01234567.to_byte_string)
  inputs = Hash.new do |h, k|
    h[k] = []
  end
  
  i = 0
  loop do
    m = i.to_byte_string.rjust(16, "\x00")
    print "\e[0G#{m.byte_string_to_hex}"
    digest = md.poor_digest(m, state)
    digest[0] = "\x00"
    digest[1] = "\x00"
    inputs[digest] << m
    return [digest, inputs[digest]] if inputs[digest].count > 1
    i += 1
  end
end

def collide_composite(md, n)
  last_generation = { 0x01234567.to_byte_string => [''.b] }
  while last_generation.values.map(&:count).sum < n do
    next_generation = Hash.new do |h, k|
      h[k] = Set[]
    end
    last_generation.each_pair do |state, inputs|
      state, colliding_inputs = collide_two_blake_composite(md, state)
      inputs.each do |input|
        next_generation[state] |= colliding_inputs.map { |new_input| input + new_input }.to_set
      end
    end
    last_generation = next_generation
  end

  puts
  puts "found #{last_generation.values.map(&:count).sum} unique inputs for collision in second half of digest"
  inputs_by_digest = {}
  last_generation.values.first.each do |input|
    digest = md.poor_digest(input, 0x01234567.to_byte_string)
    return [inputs_by_digest[digest], input] if inputs_by_digest.include?(digest)
    inputs_by_digest[digest] = input
  end
  last_generation
end

puts
puts 'finding a collision in composite hash function...'
m1, m2 = collide_composite(md, 2**8)
puts 'found a collision'
puts "m1: #{m1.byte_string_to_hex} (digest: #{md.poor_digest(m1, 0x01234567.to_byte_string).byte_string_to_hex})"
puts "m2: #{m2.byte_string_to_hex} (digest: #{md.poor_digest(m2, 0x01234567.to_byte_string).byte_string_to_hex})"
