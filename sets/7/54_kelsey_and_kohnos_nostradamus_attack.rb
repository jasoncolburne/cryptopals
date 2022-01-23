#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'set'

Cryptography = Jason::Math::Cryptography
AES = Cryptography::SymmetricKey::AdvancedEncryptionStandard
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
  end

  def digest(message, state = 0x0123.to_byte_string, pad: true)
    message = PKCS7.pad(message, 16) unless (message.length % 16).zero? and !pad
    length = 2

    Cryptography::Cipher.split_into_blocks(message, 16).each do |block|
      @aes.initialization_vector = state.rjust(16, "\x00")
      state = @aes.encrypt(block)[0..(length - 1)]
    end

    state
  end
end

def increment(bytes)
  length = bytes.length
  (bytes.byte_string_to_integer + 1).to_byte_string.rjust(length, "\x00")
end

def collide_independent_states(md, state_a, state_b)
  a = {}
  b = {}

  message = "\x00" * 16
  loop do
    digest = md.digest(message, state_a, pad: false)
    return [digest, message, b[digest]] if b.include?(digest)
    a[digest] = message

    digest = md.digest(message, state_b, pad: false)
    return [digest, a[digest], message] if a.include?(digest)
    b[digest] = message

    message = increment(message)
  end
end

def collide_to_single_block(md, states, generations = [])
  generation = []
  new_states = []
  k = Math.log2(states.length).to_i
  puts "constructing 2^#{k-1} states from 2^#{k} states..."
  states.each_slice(2) do |initial_state_a, initial_state_b|
    final_state, block_a, block_b = collide_independent_states(md, initial_state_a, initial_state_b)
    generation << {
      state: final_state,
      input_states: [initial_state_a, initial_state_b],
      blocks: [block_a, block_b]
    }
    new_states << final_state
  end
  generations << generation
  return generations if generation.count == 1
  collide_to_single_block(md, new_states, generations)
end

def collide_state_to_states(md, initial_state, target_states)
  block = "\x00" * 16
  digest = initial_state
  target_states_set = target_states.to_set
  block = increment(block) until target_states_set.include?(digest = md.digest(block, initial_state, pad: false))
  [target_states.index(digest), block]
end

k = ARGV[0].nil? ? 4 : ARGV[0].to_i
puts "constructing 2^#{k} unique digests"
digests = Set[]
digests << SecureRandom.random_bytes(2) while digests.count < 2**k
digests = digests.to_a

md = MerkleDamgardConstructionHash.new
generations = collide_to_single_block(md, digests)

# published_digest = generations.last.first[:state]
published_digest = md.digest(PKCS7.pad('', 16), generations.last.first[:state], pad: false)
puts "'prediction' made. digest published: #{published_digest.byte_string_to_hex}"

puts "time passes..."
puts "Sports team has won all the sports this year."
forged_message = "Sports team will win all the sports this year."
forged_message += ' ' * ((16 - forged_message.length) % 16)
puts "base forged message: #{forged_message}"

base_digest = md.digest(forged_message, pad: false)
i, glue = collide_state_to_states(md, base_digest, digests)
forged_message += glue
digest = digests[i]
generation_index =  i / 2 # we sliced by 2

until generations.empty?
  generation = generations.shift
  pair = generation[generation_index]
  generation_index /= 2
  forged_message += pair[:blocks][pair[:input_states].index(digest)]
  digest = pair[:state]
end

puts 'appended garbage to forged message. could have restricted to printable characters'
puts 'but that would have been slower.'
forged_digest = md.digest(forged_message)
puts "forged_digest: #{forged_digest.byte_string_to_hex}"
