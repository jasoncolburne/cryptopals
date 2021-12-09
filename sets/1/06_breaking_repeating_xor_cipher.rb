#!/usr/bin/env ruby

require 'base64'
require 'rubygems'
require 'bundler/setup'
require 'jason/math'

# this one sums to one, so we need to filter out the punctuation first
$LETTER_FREQUENCIES = {
  E: 0.111607,
  A: 0.084966,
  R: 0.075809,
  I: 0.075448,
  O: 0.071635,
  T: 0.069509,
  N: 0.066544,
  S: 0.057351,
  L: 0.054893,
  C: 0.045388,
  U: 0.036308,
  D: 0.033844,
  P: 0.031671,
  M: 0.030129,
  H: 0.030034,
  G: 0.024705,
  B: 0.020720,
  F: 0.018121,
  Y: 0.017779,
  W: 0.012899,
  K: 0.011016,
  V: 0.010074,
  X: 0.002902,
  Z: 0.002722,
  J: 0.001965,
  Q: 0.001962,
}

$PUNCTUATION_FREQUENCIES_PER_1000_WORDS = {
  :'.' => 0.006530,
  :',' => 0.006130,
  :'"' => 0.002670,
  :"'" => 0.002430,
  :'–' => 0.001530,
  :'?' => 0.000560,
  :':' => 0.000340,
  :'!' => 0.000330,
  :';' => 0.000320,
}

def fuzzy_english_distance?(text)
  result = 0.0

  spaces_frequency = text.count(' ').to_f / text.length
  result += 0.25 if spaces_frequency < 0.05

  text = text.tr(' ', '')

  $PUNCTUATION_FREQUENCIES_PER_1000_WORDS.keys.each do |symbol|
    frequency = text.count(symbol.to_s.b).to_f / text.length
    result += (frequency - $PUNCTUATION_FREQUENCIES_PER_1000_WORDS[symbol]).abs
  end

  punctuation_characters = $PUNCTUATION_FREQUENCIES_PER_1000_WORDS.keys.map(&:to_s).join
  text = text.tr(punctuation_characters.b, '')

  $LETTER_FREQUENCIES.keys.each do |symbol|
    letter = symbol.to_s
    frequency = text.count(letter + letter.downcase).to_f / text.length
    result += (frequency - $LETTER_FREQUENCIES[symbol]).abs
  end

  non_alpha_text = text.tr('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', '')

  result += non_alpha_text.length.to_f / text.length

  result
end

def break_single_byte_xor_cipher(cipher_text)
  keys_by_english_distance = Hash.new { |h, k| h[k] = [] }

  length = cipher_text.length
  0.upto(255) do |n|
    deciphered_data = (n.chr * length) ^ cipher_text
    distance = fuzzy_english_distance?(deciphered_data)  
    keys_by_english_distance[distance] << n.chr
  end

  minimum_distance = keys_by_english_distance.keys.min
  [minimum_distance, keys_by_english_distance[minimum_distance]]
end

def transpose_data(data, key_length)
  return [data] if key_length == 1

  bytes = data.bytes
  0.upto(key_length - 1).map do |offset|
    i = offset

    aggregator = ""
    while i < bytes.length
      aggregator += bytes[i].chr
      i += key_length
    end

    aggregator
  end
end

def break_repeating_xor_cipher(cipher_text, key_length_range)
  normalized_hamming_distances_by_key_length = key_length_range.map do |key_length|
    raise "Key length too long to compute hamming distance of cipher text" if key_length * 4 > cipher_text.length
    distances = (0..3).map do |i|
      Jason::Math::Cryptography.hamming_distance(cipher_text[(key_length * i)..(key_length * (i + 1) - 1)], cipher_text[(key_length * (i + 1))..(key_length * (i + 2) - 1)]).to_f / key_length
    end
    distances.sum.to_f / distances.count
  end.zip(key_length_range)
  
  lengths_to_try = normalized_hamming_distances_by_key_length.sort_by { |distance, length| distance }.first(3).map { |distance, length| length }
  
  potential_clear_texts = lengths_to_try.map do |key_length|
    distances = []
  
    key = transpose_data(cipher_text, key_length).map do |block|
      distance, characters = break_single_byte_xor_cipher(block)
      raise "Found multiple possible keys for single byte xor cipher" unless characters.count == 1
  
      distances << distance
      characters.first
    end.join
  
    [distances.sum / distances.count, key]
  end.to_h
  
  key = potential_clear_texts[potential_clear_texts.keys.min]
  Jason::Math::Cryptography.xor_cipher(cipher_text, key)
end

input = File.read(ARGV[0]).chomp.split("\n")
base64_data = input.join
data = Base64.strict_decode64(base64_data)

key_length_range = 2..64

puts break_repeating_xor_cipher(data, key_length_range)
