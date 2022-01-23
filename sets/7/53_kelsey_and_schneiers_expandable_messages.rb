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

def collide_independent_states(md, state_a, state_b = 0x0123.to_byte_string)
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

def collide_state_to_states(md, initial_state, target_states, k)
  block = "\x00" * 16
  digest = initial_state
  target_states_set = target_states.to_set
  block = increment(block) until target_states_set.include?(digest = md.digest(block, initial_state, pad: false)) && target_states.index(digest) >= k
  [target_states.index(digest), block]
end

def construct_n_block_message(components, n)
  result = ''
  length = n * 16
  result_length = 0

  minimum_remaining_component_length = components.length * 16
  components.each.with_index do |component|
    extended_block = component[:extended_block]
    minimum_remaining_component_length -= 16
    contents = extended_block.length > length - result_length - minimum_remaining_component_length ? component[:single_block] : extended_block
    result << contents
    result_length += contents.length
  end

  result
end

k = ARGV[0].nil? ? 6 : ARGV[0].to_i
block_min = [k + 2, 2**(k-1)].max
block_max = [2**k, block_min + 1].max
message_length = SecureRandom.random_number((16 * block_min)..(16 * block_max))
true_message = SecureRandom.random_bytes(message_length)
md = MerkleDamgardConstructionHash.new
true_digest = md.digest(true_message)


message_components = []
previous_digest = 0x0123.to_byte_string
k.times do |i|
  length = 16 * 2**(k - i - 1)
  prefix_blocks = SecureRandom.random_bytes(length)
  intermediate_digest = md.digest(prefix_blocks, previous_digest, pad: false)
  puts "colliding chunk of length 2^#{k - i - 1} + 1 blocks with single block"
  final_digest, final_block, single_block = collide_independent_states(md, intermediate_digest, previous_digest)
  message_components << {
    digest: final_digest,
    single_block: single_block,
    extended_block: prefix_blocks + final_block
  }
  previous_digest = final_digest
end

puts 'computing intermediate states in message digest...'
digests = []
previous_digest = 0x0123.to_byte_string
Cryptography::Cipher.split_into_blocks(true_message, 16).each do |block|
  previous_digest = md.digest(block, previous_digest, pad: block.length != 16)
  digests << previous_digest
end
digests.pop

puts 'colliding glue block...'
final_digest = message_components.last[:digest]
n = 0
glue = nil
while n < k
  n, glue = collide_state_to_states(md, final_digest, digests, k)
end

puts 'constructing forgery...'
forgery_base = construct_n_block_message(message_components, n)

true_message_blocks = (true_message.length.to_f / 16).ceil
forged_message_minimum_blocks = forgery_base.length / 16 + 2
raise 'minimum expandable message overruns authentic message (choose larger k)' if forged_message_minimum_blocks > true_message_blocks

forged_message = forgery_base + glue
forged_message += true_message[(forged_message.length)..]
forged_digest = md.digest(forged_message)

puts "true message length: #{true_message.length}"
puts "forged message length: #{forged_message.length}"
puts "true suffix length: #{forged_message.length - forgery_base.length - 16}"
puts "true digest: #{true_digest.byte_string_to_hex}"
puts "forged digest: #{forged_digest.byte_string_to_hex}"
