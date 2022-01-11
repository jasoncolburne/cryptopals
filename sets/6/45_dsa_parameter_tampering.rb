#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'set'

module BrokenSigningImplementation
  def sign(message)
    r = nil
    s = nil
    m = @digest.digest(message)[0..(@modulus_length - 1)].byte_string_to_integer

    loop do
      k = SecureRandom.random_number(1..(@q - 1))
      next if @used_k_values.include?(k)

      r = @g.modular_exponentiation(k, @p) % @q
      s = (k.modular_inverse(@q) * (m + @x * r)) % @q
      @used_k_values << k
      break
    end

    [r, s]
  end

  def verify(message, r, s)
    w = s.modular_inverse(@q)
    m = @digest.digest(message)[0..(@modulus_length - 1)].byte_string_to_integer
    u1 = (m * w) % @q
    u2 = (r * w) % @q
    v = ((@g.modular_exponentiation(u1, @p) *
          @y.modular_exponentiation(u2, @p)) % @p) % @q
    v == r
  end
end

p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b

Cryptography = Jason::Math::Cryptography
Cryptography::AsymmetricKey::DigitalSignatureAlgorithm.prepend BrokenSigningImplementation

# g = 0
g = 0
dsa = Cryptography::AsymmetricKey::DigitalSignatureAlgorithm.new(:sha_1, :'1024', p, q, g, validate_parameters: false)
dsa.generate_keypair!

raise 'failure exploiting g = 0' unless dsa.verify('two', *dsa.sign('one'))
puts 'verified signature for using an invalid message with g = 0'

# g = 1
g = p + 1
dsa = Cryptography::AsymmetricKey::DigitalSignatureAlgorithm.new(:sha_1, :'1024', p, q, g, validate_parameters: false)
_, y = dsa.generate_keypair!

z = SecureRandom.random_number(2..32)
r = y.modular_exponentiation(z, p) % q
s = (r * z.modular_inverse(q)) % q

puts 'computed magic signature from public key...'
message = SecureRandom.random_bytes(32)
raise 'failed to verify magic signature against random byte message' unless dsa.verify(message, r, s)
puts 'verified magic signature against random byte message'
