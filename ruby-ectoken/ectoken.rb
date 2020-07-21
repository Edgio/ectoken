require 'base64'
require 'digest'
require 'openssl'
require 'optparse'

def encrypt(key, token)
  digest = Digest::SHA256.digest(key)
  cipher = OpenSSL::Cipher::AES.new(256, :GCM).encrypt
  iv = cipher.random_iv
  cipher.iv = iv
  cipher.key = digest
  cipher_text = cipher.update(token) + cipher.final
  cipher_with_iv = iv + cipher_text + cipher.auth_tag
  Base64.urlsafe_encode64(cipher_with_iv)
end

def decrypt(key, token)
  digest = Digest::SHA256.digest(key)
  decoded_token = Base64.urlsafe_decode64(token)
  iv = decoded_token[0..11]
  decipher_text = decoded_token[12..decoded_token.length-17]
  decipher = OpenSSL::Cipher::AES.new(256, :GCM).decrypt
  decipher.iv = iv
  decipher.key = digest
  decipher.update(decipher_text)
end

@options = {}

option_parser = OptionParser.new do |opts|
  opts.on('-k', '--key=KEY', 'Key to encrypt or decrypt') do |v|
    @options[:key] = v
  end

  opts.on('-t', '--token=TOKEN', 'Token to encrypt or decrypt') do |v|
    @options[:token] = v
  end

  opts.on('-d', '--decrypt', 'Use this option to decrypt data') do |v|
    @options[:decrypt] = true
  end
end

option_parser.parse!

if @options[:key].nil? || @options[:token].nil?
  puts option_parser.help
  exit 1
end

case @options[:decrypt].nil?
when true
  puts encrypt(@options[:key], @options[:token])
when false
  puts decrypt(@options[:key], @options[:token])
end
