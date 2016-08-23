require "base64"
require "openssl"

def set2_ex12
    ## I admit that I will skip the part to determine the block length
    ## and the algo used (cbc vs ecb).
    ## blocklength => call with 1 byte...
    ## algo used => call with two blocks equal
    puts "[+] Set2 - Ex12:"

    bsize = 16
    random_key = Random.new.bytes(bsize)
    random_pad = Base64.decode64 "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

    ## return aes_ecb using the random_key and padding random_pad to the 
    ## data
    encrypt_padding = lambda do |data|
        cipher = OpenSSL::Cipher.new('AES-128-ECB')
        cipher.encrypt
        cipher.key = random_key
        input = data + random_pad
        cipher.update(input) + cipher.final
    end

    ## will compute the dico of encrypting prefix+i with i = (0...256)
    ## compute encryption of prefix, then find the byte
    onebyte = lambda do |prefix| 
        raise 'wrong size prefix' unless prefix.size == bsize-1
        ## do the dic
        dic = (0..256).inject({}) do |acc,i|
            data = prefix + i.chr 
            cipher = encrypt_padding.call(data)
            acc[cipher] = i.chr
            acc
        end
        cipher = encrypt_padding.call(prefix)
        raise 'whut? no byte found...' if dic[cipher].nil?
        dic[cipher]
    end

    ## will decrypt the random_pad !

    puts Base64.encode64(encrypt_padding.call("youdontknow"))
end
