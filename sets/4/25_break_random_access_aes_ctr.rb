#!/usr/bin/env ruby

require 'set'
require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'active_support/all'

data = File.read(ARGV[0])
cipher_text = data.base64_to_byte_string
key = 'YELLOW SUBMARINE'

cipher = Jason::Math::Cryptography::AdvancedEncryptionStandard.new(:ecb_128, key)
clear_text = cipher.decrypt(cipher_text)

class Cryptor
  def initialize(clear_text)
    key = SecureRandom.random_bytes(32)
    @initialization_vector = SecureRandom.random_bytes(16)
    @cipher = Jason::Math::Cryptography::Cipher.new(:aes_256_ctr, key)
    @clear_text = clear_text
  end

  def cipher_text
    @cipher.initialization_vector = @initialization_vector
    @cipher.encrypt(@clear_text)
  end

  def edit(cipher_text, offset, new_text)
    raise 'Here is some information!' if new_text.length + offset > cipher_text.length

    @cipher.initialization_vector = @initialization_vector
    clear_text = @cipher.decrypt(cipher_text)
    message = offset.zero? ? '' : clear_text[0..(offset - 1)]
    message += new_text
    message += clear_text[(offset + new_text.length)..-1]
    @cipher.initialization_vector = @initialization_vector
    @cipher.encrypt(message)
  end
end

cryptor = Cryptor.new(clear_text)
cipher_text = cryptor.cipher_text

old_length = clear_text.length
clear_text = ''

search_space = Jason::Math::Utility::LanguageDetector.ordered_search_space
i = 0
loop do
  search_space.each do |char|
    new_cipher_text = cryptor.edit(cipher_text, i, char)
    if new_cipher_text[i] == cipher_text[i]
      clear_text << char.b
      puts char
      break
    end
    print '.'
  end
  i += 1
rescue
  puts
  break
end

puts clear_text
puts "old_length: #{old_length}, new_length: #{clear_text.length}"
