#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'zlib'

Cryptography = Jason::Math::Cryptography
AES = Cryptography::SymmetricKey::AdvancedEncryptionStandard

class CompressionOracle
  def format_request(clear_text)
    request = <<EOT
POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: #{clear_text.length}
#{clear_text}
EOT
    request
  end

  def compress(request)
    Zlib::Deflate.deflate(request)
  end

  def gcm_request_length(clear_text)
    request = format_request(clear_text)
    compressed = compress(request)
    key = SecureRandom.random_bytes(16)
    aes = AES.new(:gcm_128, key)
    aes.initialization_vector = SecureRandom.random_bytes(16)
    aes.encrypt(compressed, '')[0].length
  end

  def cbc_request_length(clear_text)
    request = format_request(clear_text)
    compressed = compress(request)
    key = SecureRandom.random_bytes(16)
    aes = AES.new(:cbc_128, key)
    aes.initialization_vector = SecureRandom.random_bytes(16)
    aes.encrypt(compressed).length
  end
end

oracle = CompressionOracle.new

@possible_characters = "\nABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
@padding_characters = '!@#$%^&*-`~()[]{}'

puts "using compression ratio side channel attack on gcm oracle to determine session_id..."

initial_guess = 'session_id='
@lengths = {
  initial_guess => 0
}
print "\e[0G#{initial_guess}"
guess_length = initial_guess.length
loop do
  relevant_lengths = @lengths.select { |guess, _| guess.length == guess_length }
  min = relevant_lengths.min_by { |_, request_length| request_length }[1]
  relevant_guesses = relevant_lengths.select { |_, request_length| request_length == min }.map { |guess, _| guess }
  break if relevant_guesses.count == 1 && relevant_guesses.first.end_with?("\n")

  relevant_guesses.reject! { |guess| guess.end_with?("\n") }
  relevant_guesses.each do |base_guess|
    @possible_characters.each_char do |char|
      guess = base_guess + char
      print "\e[0G#{guess.tr("\n", '')}  "
      @lengths[guess] = oracle.gcm_request_length(guess * 3)
    end
  end

  guess_length += 1
end

best_guess = @lengths.select { |guess, _| guess.length == guess_length - 1 && !guess.end_with?("\n") }.min_by { |_, request_length| request_length }[0]
puts "\e[0G#{best_guess.tr("\n", '')}  "
puts "decoded session_id: #{best_guess.split('=')[1].base64_to_byte_string}"

puts "using compression ratio side channel attack on cbc oracle to determine session_id..."

def compute_padding(guess, oracle)
  original_length = oracle.cbc_request_length(guess)
  16.times do |i|
    padding = @padding_characters[0..i]
    length = oracle.cbc_request_length(padding + guess)
    return padding if length > original_length
  end
end

initial_guess = 'session_id='
@lengths = {
  initial_guess => 0
}
print "\e[0G#{initial_guess}"
guess_length = initial_guess.length
loop do
  relevant_lengths = @lengths.select { |guess, _| guess.length == guess_length }
  min = relevant_lengths.min_by { |_, request_length| request_length }[1]
  relevant_guesses = relevant_lengths.select { |_, request_length| request_length == min }.map { |guess, _| guess }
  break if relevant_guesses.count == 1 && relevant_guesses.first.end_with?("\n")

  relevant_guesses.reject! { |guess| guess.end_with?("\n") }
  relevant_guesses.each do |base_guess|
    padding = compute_padding((base_guess + '!') * 3, oracle)
    @possible_characters.each_char do |char|
      guess = base_guess + char
      print "\e[0G#{guess.tr("\n", '')}  "
      @lengths[guess] = oracle.cbc_request_length(padding + guess * 3)
    end
  end

  guess_length += 1
end

best_guess = @lengths.select { |guess, _| guess.length == guess_length - 1 && !guess.end_with?("\n") }.min_by { |_, request_length| request_length }[0]
puts "\e[0G#{best_guess}  "
puts "decoded session_id: #{best_guess.split('=')[1].base64_to_byte_string}"