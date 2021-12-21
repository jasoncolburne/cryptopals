#!/usr/bin/env ruby

require 'set'
require 'rubygems'
require 'bundler/setup'
require 'jason/math'
require 'securerandom'
require 'curses'

data = File.read(ARGV[0])

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
    @top = (Curses.lines - @height) / 2
    @left = (Curses.cols - @width) / 2

    @top = [0, @top].max

    @position = [@top, @left]

    @key_stream = [nil] * @width
  end

  def attempt_statistical_break
    range = 0..(@width - 1)
    
    cipher_text_character_lists = @cipher_texts.map { |cipher_text| cipher_text.chars }
    longest_character_list = cipher_text_character_lists.max_by { |list| list.count }
    cipher_text_character_lists.delete(longest_character_list)
    characters = longest_character_list.zip(*(cipher_text_character_lists)).map(&:compact)
    
    range.each do |i|
      minimum_distance = Float::INFINITY
      (0..255).each do |n|
        relevant_string = characters[i].join
        potential_clear_text = (relevant_string ^ (n.chr * relevant_string.length))
        distance = Jason::Math::Utility::LanguageDetector.distance(potential_clear_text)
        if distance < minimum_distance
          minimum_distance = distance
          @key_stream[i] = n.chr
        end
      end
    end
  end

  def redraw
    Curses.clear
    @cipher_texts.each_with_index do |cipher_text, y|
      break if @top + y >= Curses.lines
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

ui = UI.new(data)
ui.attempt_statistical_break
ui.run
