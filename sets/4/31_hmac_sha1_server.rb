#!/usr/bin/env ruby

require 'base64'
require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'securerandom'
require 'cgi'
require 'sinatra'

hmac = Jason::Math::Cryptography::HashedMessageAuthenticationCode.new(:sha_1, SecureRandom.random_bytes(64))

post '/test' do
  tempfile = params[:file][:tempfile]
  data = tempfile.read

  mac = hmac.digest(data)
  signature = params[:signature].hex_to_byte_string

  if signature.length != mac.length
    status 500
    body "internal server error\n"
    return
  end

  signature.each_char.each_with_index do |character, index|
    if character != mac[index]
      status 500
      body "internal server error\n"
      return nil
    end

    sleep(0.050)
  end

  status 200
  body "ok\n"
end
