#!/usr/bin/env ruby

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

data = File.read(ARGV[0])
input = data.chomp.split("\n")

broken_ciphertexts = input.map(&:hex_to_byte_string).map do |cipher_text|
  distance, keys = break_single_byte_xor_cipher(cipher_text)
  [distance, (keys.first * cipher_text.length) ^ cipher_text]
end.to_h

pp broken_ciphertexts[broken_ciphertexts.keys.min]
