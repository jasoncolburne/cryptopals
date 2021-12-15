#!/usr/bin/env ruby

require 'set'
require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'securerandom'

data = <<EOT
MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
EOT

class Encryptor
  def initialize(algorithm, key_length, messages)
    key = SecureRandom.random_bytes(key_length)
    @messages = messages
    @cipher = Jason::Math::Cryptography::Cipher.new(algorithm, key)
  end

  def encrypt(clear_text = nil)
    message = @messages[SecureRandom.random_number(@messages.count)]
    initialization_vector = SecureRandom.random_bytes(16)
    [@cipher.encrypt(message, initialization_vector), initialization_vector]
  end

  def decrypt(cipher_text, initialization_vector, strip_padding = true)
    @cipher.decrypt(cipher_text, initialization_vector, strip_padding)
  end
end

messages = data.chomp("\n").split("\n").map { |line| line.base64_to_byte_string }
encryptor = Encryptor.new(:aes_128_cbc, 16, messages)

lengths = (0..24).to_a.map do
  cipher_text, initialization_vector = encryptor.encrypt
  cipher_text.length
end

block_size = lengths.uniq.combination(2).map { |a, b| (b - a).abs }.reject { |length| length.zero? }.min
puts "block size: #{block_size}"

def xor_clear_text_bytes(cipher_text, initialization_vector, bytes, index, block_size = 16)
  bytes_length = bytes.length
  raise "Cannot xor across blocks" if bytes_length > block_size - index % block_size

  index %= cipher_text.length

  if index < block_size
    prefix_range = 0..(index - 1)
    xor_range = index..(index + bytes_length - 1)
    suffix_range = (index + bytes_length)..-1
    initialization_vector = initialization_vector[prefix_range] + (initialization_vector[xor_range] ^ bytes) + initialization_vector[suffix_range]
  else
    prefix_range = 0..(index - block_size - 1)
    xor_range = (index - block_size)..(index - block_size + bytes_length - 1)
    suffix_range = (index - block_size + bytes_length)..-1
    cipher_text = cipher_text[prefix_range] + (cipher_text[xor_range] ^ bytes) + cipher_text[suffix_range]
  end

  [cipher_text, initialization_vector]
end

def cbc_replace_offset_bytes(cipher_text, initialization_vector, bytes, index, block_size = 16)
  bytes_length = bytes.length

  index %= cipher_text.length

  if index < block_size
    prefix_range = index.zero? ? 1..0 : 0..(index - 1)
    xor_range = index..(index + bytes_length - 1)
    suffix_range = (index + bytes_length)..-1

    initialization_vector = initialization_vector[prefix_range] + bytes + initialization_vector[suffix_range]
  else
    offset = index - block_size
    prefix_range = offset.zero? ? 1..0 : 0..(offset - 1)
    xor_range = (offset)..(offset + bytes_length - 1)
    suffix_range = (offset + bytes_length)..-1

    cipher_text = cipher_text[prefix_range] + bytes + cipher_text[suffix_range]
  end

  [cipher_text, initialization_vector]
end

padding_length = nil
cipher_text, initialization_vector = encryptor.encrypt
(1..block_size).each do |i|
  altered_cipher_text, altered_initialization_vector = xor_clear_text_bytes(cipher_text, initialization_vector, "\xff", -i, block_size)

  begin
    encryptor.decrypt(altered_cipher_text, altered_initialization_vector)
    padding_length = i - 1
    break
  rescue
    next
  end
end

padding_length = block_size if padding_length.nil?

clear_text = ([padding_length] * padding_length).pack('C*')

puts "padding_length: #{padding_length}"

cipher_text_length = cipher_text.length
current_padding = ([padding_length] * padding_length).pack('C*')
offset = cipher_text_length - padding_length
limit = (offset / block_size + 1) * block_size - 1
if offset < block_size
  xor_mask = initialization_vector[offset..limit] ^ current_padding
else
  range = (offset - block_size)..(limit - block_size)
  xor_mask = cipher_text[range] ^ current_padding
end

(cipher_text_length - padding_length).times do |i|
  padding_length %= block_size

  blocks_to_strip = xor_mask.length / block_size
  index = -(xor_mask.length % block_size) - 1
  range = 0..(-(blocks_to_strip * block_size) - 1)
  relevant_mask = xor_mask[range]
  relevant_ciphertext = cipher_text[range]

  (0..255).each do |n|
    char = n.chr

    mask = char + relevant_mask
    padding = ([padding_length + 1] * (padding_length + 1)).pack('C*')
    payload = (padding ^ mask).b
    altered_cipher_text, altered_initialization_vector = cbc_replace_offset_bytes(relevant_ciphertext, initialization_vector, payload, index, block_size)

    begin
      encryptor.decrypt(altered_cipher_text, altered_initialization_vector)

      value = if xor_mask.length >= cipher_text_length - block_size
        altered_initialization_vector[index] ^ (padding_length + 1).chr
      else
        altered_cipher_text[index - block_size] ^ (padding_length + 1).chr
      end

      xor_mask = value + xor_mask

      break
    rescue
      raise "Could not determine character #{i + 1}" if n == 255
      next
    end
  end

  padding_length += 1
  padding_length %= block_size
end

to_unmask = initialization_vector + cipher_text[0..(-block_size - 1)]

puts Jason::Math::Cryptography::PKCS7.strip(to_unmask ^ xor_mask, block_size)
