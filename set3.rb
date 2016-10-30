require 'base64'
require 'securerandom'
require 'openssl'

module Set3

    @@bsize = 16

    class Server
         @msgs = %w{
        MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
        MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
        MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
        MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
        MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
        MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
        MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
        MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
        MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
        MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
         }
         attr_accessor :key, :msg
         def self.msgs 
             @msgs
         end
         
         def initialize
             @cipher = OpenSSL::Cipher.new('AES-128-CBC')
             # choose msg at random, decrypt it, pad it
             @msg = Base64.decode64(self.class.msgs[Random.new.rand(self.class.msgs.size)-1])
             @msgPadded = pkcs7_padding @msg
         end

         ## encrypt the chosen message, returns the ciphertext + IV
         def encrypt 
             @cipher.encrypt
             @key ||= @cipher.random_key
             iv = @cipher.random_iv
             enc = @cipher.update(@msg) + @cipher.final
             [enc,iv] 
         end

         ## oracle returns true if the decrypted data has valid padding or false
         # otherwise. Since openssl is doing the bad work for us, it's just
         # catching the exception...
         def oracle ciphertext,iv
            decipher = @cipher.decrypt
            decipher.key = @key
            decipher.iv = iv
            decipher.update(ciphertext) + decipher.final
            true
            raise OpenSSl::Cipher::CipherError
                false
         end

         def pkcs7_padding data
             mod = data.size % 16 
             addOffset = mod == 0 ? 16 : 16 - mod
             data + ([addOffset] * addOffset).pack("C*")
         end
    end

    def self.exo17
        puts "[+] Set3 :: exo17"
        server = Server.new
        encrypted,iv = server.encrypt
        puts "[+] Creating server ... IV #{iv.unpack("H*").first} Cipher: #{encrypted.unpack("H*").first}"
    end

end
