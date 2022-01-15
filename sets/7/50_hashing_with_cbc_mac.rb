#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'cgi'

module BrokenCBCImplementation
  def encrypt_cbc(clear_text)
    length = clear_text.length
    iterations = (length.to_f / @block_size).ceil
    cipher_text = ''.b

    iterations.times do |i|
      to_xor = clear_text[(i * @block_size)..[(i + 1) * @block_size - 1, length - 1].min]
      to_xor = Jason::Math::Cryptography::PKCS7.pad(to_xor, @block_size) unless to_xor.length == @block_size
      to_cipher = Jason::Math::Utility.xor(to_xor, @initialization_vector)
      @initialization_vector = cipher(to_cipher)
      cipher_text << @initialization_vector
    end

    cipher_text
  end
end

AES = Jason::Math::Cryptography::SymmetricKey::AdvancedEncryptionStandard
AES.prepend BrokenCBCImplementation

key = 'YELLOW SUBMARINE'
@aes = AES.new(:cbc_128, key)

def increment(byte_string)
  bytes = byte_string.bytes
  done = false
  bytes.map do |byte|
    if done
      byte
    else
      result = byte + 1
      if result >= 127
        result = 32
      else
        done = true
      end
      result
    end
  end.map(&:chr).join
end

def collide(malicious_snippet, old_snippet)
  raise "malicious code must be a multiple of block size" unless (malicious_snippet.length % 16).zero?
  glue = "\x00".b
  random_bytes = "\x20".b * 16
  # seems like this will take about 3.25 million attempts.. ((256/96)^16) / 2
  i = 0
  until glue.bytes.all? { |byte| byte >= 32 && byte < 127 }
    i += 1
    print "\e[0G#{i} attempts"
    random_bytes = increment(random_bytes)
    @aes.initialization_vector = "\x00".b * 16
    glue = @aes.encrypt(malicious_snippet + random_bytes)[-16..] ^ old_snippet[0..15]
  end
  puts

  malicious_snippet + random_bytes + glue + old_snippet[16..]
end

old_snippet = "alert('MZA who was that?');\n".b
@aes.initialization_vector = "\x00".b * 16
valid_mac = @aes.encrypt(old_snippet)[-16..].byte_string_to_hex
print 'valid code: '
pp old_snippet
puts "computed mac on valid code: #{valid_mac}"

puts 'creating a collision (this can take a long time - 2687937 iterations to be precise)...'
malicious_snippet = "alert('Ayo, the Wu is back!');//".b
forged_snippet = collide(malicious_snippet, old_snippet)
@aes.initialization_vector = "\x00".b * 16
forgery_mac = @aes.encrypt(forged_snippet)[-16..].byte_string_to_hex
print 'forged code: '
pp forged_snippet
puts "computed mac on forged code: #{forgery_mac}"
f = File.open('./50_forged_alert.js', 'w+b')
f.write(forged_snippet)
f.close
