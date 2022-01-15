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
      to_xor = to_xor.ljust(@block_size, "\x00")
      to_cipher = Jason::Math::Utility.xor(to_xor, @initialization_vector)
      @initialization_vector = cipher(to_cipher)
      cipher_text << @initialization_vector
    end

    cipher_text
  end
end

Jason::Math::Cryptography::SymmetricKey::AdvancedEncryptionStandard.prepend BrokenCBCImplementation

key = SecureRandom.random_bytes(16)
@aes = Jason::Math::Cryptography::SymmetricKey::AdvancedEncryptionStandard.new(:cbc_128, key)
@user_ids = {
  lucifer: 0,
  victim: 1,
  recipient: 2,
  glerups: 3
}
@names = @user_ids.each_pair.map { |name, id| [id, name] }.to_h
@auth_tokens = {}
@passwords = {
  0 => 'ultra secure password',
  1 => 'password',
  2 => 'drowssap',
  3 => 'glerups'
}
@balances = {
  0 => 100,
  1 => 3_392_800,
  2 => 10,
  3 => 3000
}

def user_id(name)
  @user_ids[name.to_sym] || raise('access denied')
end

def login(name, password)
  user_id = @user_ids[name.to_sym]
  if password == @passwords[user_id]
    token = SecureRandom.random_bytes(16)
    @auth_tokens[token] = user_id
    token
  else
    puts "access denied"
  end
end


def create_request_v1(auth_token, to, amount, initialization_vector)
  from = @auth_tokens[auth_token]
  raise 'access denied' if from.nil?
  raise 'incorrect type for amount' unless amount.is_a? Numeric
  to = @user_ids[to.to_sym]
  raise 'invalid user name' if to.nil?

  payload = "from=#{from}&to=#{to}&amount=#{amount}".b

  @aes.initialization_vector = initialization_vector
  tag = @aes.encrypt(payload)[-16..]
  payload + initialization_vector + tag
end

def create_request_v2(auth_token, to)
  from = @auth_tokens[auth_token]
  raise 'access denied' if from.nil?
  tx_list = to.each.map do |name, amount|
    user_id = @user_ids[name.to_sym]
    raise 'invalid user name' if user_id.nil?
    raise 'incorrect type for amount' unless amount.is_a? Numeric
    "#{user_id}:#{amount}"
  end.join(';')
  payload = "from=#{from}&tx_list=#{tx_list}".b

  @aes.initialization_vector = "\x00".b * 16
  tag = @aes.encrypt(payload)[-16..]
  payload + tag
end

def forge_request_v1!
  puts 'making request to get user_id...'
  auth_token = login('lucifer', 'ultra secure password')
  initialization_vector = SecureRandom.random_bytes(16)
  request = create_request_v1(auth_token, 'lucifer', 100, initialization_vector)
  raise 'server rejected valid request' unless accept_request_v1(request)
  message = request[0..-33]
  parameters = message.split('&').map { |pair| pair.split('=').map.with_index { |x, i| i.zero? ? x.to_sym : x.to_i } }.to_h
  to = parameters[:from]

  puts 'observing request for large transfer...'
  auth_token = login('victim', 'password')
  initialization_vector = SecureRandom.random_bytes(16)
  request = create_request_v1(auth_token, 'recipient', 1_000_000, initialization_vector)
  raise 'server rejected valid request' unless accept_request_v1(request)

  puts 'forging message to liberate money...'
  message = request[0..-33]
  parameters = message.split('&').map { |pair| pair.split('=').map.with_index { |x, i| i.zero? ? x.to_sym : x.to_i } }.to_h
  from = parameters[:from]

  old_tag = request[-16..]
  initialization_vector = request[-32..-17]

  forged_message = "from=#{from}&to=#{to}&amou"
  initialization_vector = (message[0..15] ^ forged_message) ^ initialization_vector
  tag = old_tag

  forged_request = forged_message + message[16..] + initialization_vector + tag

  accept_request_v1(forged_request)
end

def forge_request_v2!
  puts 'making request to get user_id...'
  auth_token = login('lucifer', 'ultra secure password')
  request = create_request_v2(auth_token, [['lucifer', 100]])
  raise 'server rejected valid request' unless accept_request_v2(request)
  message = request[0..-17]
  parameters = message.split('&').map { |pair| pair.split('=').map.with_index { |x, i| i.zero? ? x.to_sym : x } }.to_h
  to = parameters[:from].to_i

  puts 'observing requests for large transfer of the correct length...'

  auth_token = login('victim', 'password')
  potential_recipients = %w[recipient glerups]

  request = "j"

  while request.length % 16 != 0
    recipients = 3.times.map do
      recipient_selection = SecureRandom.random_number(0..1)
      name = potential_recipients[recipient_selection]
      amount = SecureRandom.random_number(1..1280)
      [name, amount]
    end
    request = create_request_v2(auth_token, recipients)
    raise 'server rejected valid request' unless accept_request_v2(request)
  end

  puts 'found a message which is a multiple of block size'  
  puts 'forging message to liberate money...'
  message = request[0..-17]
  malicious_text = ";#{to}:1000000"
  old_tag = request[-16..]

  @aes.initialization_vector = old_tag
  new_tag = @aes.encrypt(malicious_text)[-16..]

  forged_request = message + malicious_text + new_tag
  accept_request_v2(forged_request)
end

def verify_mac(message, initialization_vector, tag)
  @aes.initialization_vector = initialization_vector
  computed_tag = @aes.encrypt(message)[-16..]
  Jason::Math::Cryptography.secure_compare(computed_tag, tag)
end

def transfer_money(from, to, amount)
  raise 'insufficient funds' unless @balances[from] >= amount

  puts "transferring $#{amount} from #{@names[from]} to #{@names[to]}..."
  @balances[from] -= amount
  @balances[to] += amount
end

def accept_request_v1(payload)
  tag = payload[-16..]
  initialization_vector = payload[-32..-17]
  message = payload[0..-33]

  verified = verify_mac(message, initialization_vector, tag)

  if verified
    parameters = message.split('&').map { |pair| pair.split('=').map.with_index { |x, i| i.zero? ? x.to_sym : x.to_i } }.to_h
    transfer_money(parameters[:from], parameters[:to], parameters[:amount])
  else
    puts 'access denied'
  end

  verified
end

def accept_request_v2(payload)
  tag = payload[-16..]
  message = payload[0..-17]

  verified = verify_mac(message, "\x00".b * 16, tag)

  if verified
    parameters = message.split('&').map { |pair| pair.split('=').map.with_index { |x, i| i.zero? ? x.to_sym : x } }.to_h
    from = parameters[:from].to_i
    transactions = parameters[:tx_list].split(';').map { |pair| pair.split(':').map(&:to_i) }
    total = transactions.map { |transaction| transaction[1] }.sum
    raise "insufficient funds" unless @balances[from] >= total
    transactions.each do |to, amount|
      transfer_money(from, to, amount)
    end
  else
    puts 'access denied'
  end

  verified
end


forge_request_v1!

puts
puts 'bank has adjusted their protocol'
puts

forge_request_v2!
