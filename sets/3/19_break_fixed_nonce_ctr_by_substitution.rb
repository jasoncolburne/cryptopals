#!/usr/bin/env ruby

require 'set'
require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'securerandom'
require 'curses'

data = <<EOT
SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
VG8gcGxlYXNlIGEgY29tcGFuaW9u
QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
U2hlIHJvZGUgdG8gaGFycmllcnM/
VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
SW4gdGhlIGNhc3VhbCBjb21lZHk7
SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
VHJhbnNmb3JtZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
EOT

class Cryptor
  def initialize
    key = SecureRandom.random_bytes(32)
    @nonce = "\x00" * 8
    @cipher = Jason::Math::Cryptography::Cipher.new(:aes_256_ctr, key)
  end

  def encrypt(clear_text)
    clear_text.to_blocks(16).each_with_index.map do |block, counter|
      initialization_vector = @nonce + [counter].pack('Q<*')
      @cipher.initialization_vector = initialization_vector
      @cipher.encrypt(block)
    end.join
  end
end

class UI
  ARROWS = {
    'A' => [-1, 0],
    'B' => [1, 0],
    'C' => [0, 1],
    'D' => [0, -1],
  }

  def initialize(data)
    @cryptor = Cryptor.new
    @cipher_texts = data.chomp.split("\n").map(&:base64_to_byte_string).map { |sentence| @cryptor.encrypt(sentence) }

    Curses.init_screen
    Curses.raw
    Curses.noecho

    @height = @cipher_texts.length
    @width = @cipher_texts.map(&:length).max
    @top    = (Curses.lines - @height) / 2
    @left   = (Curses.cols - @width) / 2

    @position = [@top, @left]

    @key_stream = [nil] * @width
  end

  def redraw
    @cipher_texts.each_with_index do |cipher_text, y|
      Curses.setpos(@top + y, @left)
      (@left..(@left + cipher_text.length - 1)).each do |x|
        x -= @left
        value = @key_stream[x] ? @key_stream[x] ^ cipher_text[x] : '*'
        Curses.addch(value)
      end
    end
    Curses.refresh
  end

  def process(key_stroke)
    if key_stroke == 27
      Curses.getch
      delta = ARROWS[Curses.getch]
      @position[0] += delta[0]
      @position[1] += delta[1]
    else
      y = @position[0] - @top
      x = @position[1] - @left

      @key_stream[x] = @cipher_texts[y][x] ^ key_stroke.chr.b
    end
  end

  def run
    key_stroke = nil
    begin
      Curses.clear
      until key_stroke == 17
        redraw
        Curses.setpos(*@position)
        key_stroke = Curses.getch
        process(key_stroke) unless key_stroke == 17
      end
    ensure
      Curses.close_screen
    end
    pp @key_stream.join
  end
end

UI.new(data).run
