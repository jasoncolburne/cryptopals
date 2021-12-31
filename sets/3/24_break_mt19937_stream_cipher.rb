#!/usr/bin/env ruby

require 'set'
require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'active_support/all'

@key_max_plus_one = 2**16

def random_alpha(minimum, maximum)
  SecureRandom.alphanumeric(SecureRandom.random_number(maximum - minimum) + minimum)
end

key = SecureRandom.random_number(@key_max_plus_one)
cipher = Jason::Math::Cryptography::Cipher.new(:xor_mt19937_64_stream, key)

known_clear_text = ' known clear text '
puts "generating some data containing the phrase '#{known_clear_text}'"
clear_text = random_alpha(3, 20) + known_clear_text + random_alpha(3, 20)
puts "encrypting the message using the :mt19937_64_stream cipher keyed/seeded with a 'random' 16-bit integer"
cipher_text = cipher.encrypt(clear_text)

def recover_key(cipher_text, known_clear_text)
  cipher = Jason::Math::Cryptography::SymmetricKey::ExclusiveOrCipher.new(:mt19937_64_stream, 0)

  (0..@key_max_plus_one).each do |key|
    cipher.instance_variable_get(:@prng).seed = key
    clear_text = cipher.decrypt(cipher_text)
    return key if clear_text.include?(known_clear_text)
  end
end

puts 'recovering key by brute force...'
recovered_key = recover_key(cipher_text, known_clear_text)
puts "recovered key: #{recovered_key}"
puts Jason::Math::Cryptography::Cipher.new(:xor_mt19937_64_stream, recovered_key).decrypt(cipher_text)

def generate_bad_token
  token_clear_text = "#{random_alpha(3, 7)} secret token sauce #{random_alpha(3, 7)}"
  key = Time.now.to_i % @key_max_plus_one
  Jason::Math::Cryptography::Cipher.new(:xor_mt19937_64_stream, key).encrypt(token_clear_text)
end

puts 'generating two tokens with common data at random times in the next few minutes...'
sleep(SecureRandom.random_number(60) + 30)
token_a = generate_bad_token
sleep(SecureRandom.random_number(60) + 30)
token_b = generate_bad_token
sleep(SecureRandom.random_number(60) + 30)

def break_tokens(token_a, token_b, time_range)
  lower_bound = time_range.first.to_i
  upper_bound = time_range.last.to_i

  decoded_tokens_a = {}
  decoded_tokens_b = {}

  cipher = Jason::Math::Cryptography::SymmetricKey::ExclusiveOrCipher.new(:mt19937_64_stream, 0)

  puts "generating all clear_texts for each cipher_text using keys based on time range #{time_range}"
  upper_bound.downto(lower_bound).each do |key|
    cipher.instance_variable_get(:@prng).seed = key % @key_max_plus_one
    token_a_clear_text = cipher.decrypt(token_a)
    decoded_tokens_a[key] = token_a_clear_text
    cipher.instance_variable_get(:@prng).seed = key % @key_max_plus_one
    token_b_clear_text = cipher.decrypt(token_b)
    decoded_tokens_b[key] = token_b_clear_text
  end

  substrings = {}
  puts 'analyzing for common substrings...'
  decoded_tokens_a.each_pair do |key_a, token_clear_text_a|
    decoded_tokens_b.each_pair do |key_b, token_clear_text_b|
      substrings[[key_a, key_b]] = Jason::Math::Utility.longest_common_substring([token_clear_text_a, token_clear_text_b])
    end
  end

  puts 'selecting best match for english'
  substrings.select! { |_key, substring| substring.length >= 8 }
  substrings.min_by { |_key, substring| Jason::Math::Utility::LanguageDetector.distance(substring) }
end

puts 'inspecting tokens for common content to break keys'
result = break_tokens(token_a, token_b, (10.minutes.ago)..(30.seconds.ago))
raise 'could not break tokens :/' if result.nil?

keys, substring = result
key_a, key_b = keys
key_a = key_a % @key_max_plus_one
key_b = key_b % @key_max_plus_one
print 'key_a: '
pp key_a
print 'key_b: '
pp key_b
clear_text_a = Jason::Math::Cryptography::Cipher.new(:xor_mt19937_64_stream, key_a).decrypt(token_a)
clear_text_b = Jason::Math::Cryptography::Cipher.new(:xor_mt19937_64_stream, key_b).decrypt(token_b)
p "token a: '#{clear_text_a}'"
p "token b: '#{clear_text_b}'"
p "common string: '#{substring}'"

def generate_token
  prng = Jason::Math::Cryptography::PseudoRandomNumberGeneration::MersenneTwister19937.new(:mt19937_64, Time.now.to_i % @key_max_plus_one)
  Jason::Math::Cryptography::PseudoRandomNumberGeneration::PRNGByteStream.new(prng, 8).take_bytes(20)
end

def generated_from_time_seeded_mt19937_64?(token, time_range)
  token_length = token.length

  lower_bound = time_range.first.to_i
  upper_bound = time_range.last.to_i

  prng = Jason::Math::Cryptography::PseudoRandomNumberGeneration::MersenneTwister19937.new(:mt19937_64, 0)
  byte_stream = Jason::Math::Cryptography::PseudoRandomNumberGeneration::PRNGByteStream.new(prng, 8)
  upper_bound.downto(lower_bound).each do |key|
    prng.seed = key % @key_max_plus_one
    return true if byte_stream.take_bytes(token_length) == token
  end
  false
end

puts "generating a token using a randomly seeded mt19937_64 bytestream sometime in the next couple minutes..."
sleep(SecureRandom.random_number(60) + 30)
token = generate_token
sleep(SecureRandom.random_number(60) + 30)

generated = generated_from_time_seeded_mt19937_64?(token, (5.minutes.ago)..(30.seconds.ago))
puts "generated_from_time_seeded_mt19937_64?(token) #{generated}"

fake_token = SecureRandom.random_bytes(20)
generated = generated_from_time_seeded_mt19937_64?(fake_token, (5.minutes.ago)..(30.seconds.ago))
puts "generated_from_time_seeded_mt19937_64?(fake_token) #{generated}"
