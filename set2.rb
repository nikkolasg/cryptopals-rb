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
    start_length = random_pad.size + (-random_pad.size) % bsize 

    puts "[+] random_pad size #{random_pad.size}"
    puts "[+] gibberish bytes start length #{start_length}"
    ## return aes_ecb using the random_key and padding random_pad to the 
    ## data. data is bytes.
    oracle = lambda do |data|
        cipher = OpenSSL::Cipher.new('AES-128-ECB')
        cipher.encrypt
        cipher.key = random_key
        input = data.pack("c*") + random_pad
        cipher.update(input) + cipher.final
    end

    ## will compute the dico of encrypting prefix+plain+i with i = (0...256)
    ## prefix = gibberish bytes, plain = the first decrypted bytes
    onebyte = lambda do |prefix,plain| 
        raise "wrong size prefix #{(prefix+plain).size} vs #{bsize-1}" unless ((prefix+plain).size%bsize) == bsize-1
        ## do the dic
        dic = (0...256).inject({}) do |acc,i|
            data = prefix + plain + [i]
            raise "wrong size data #{data.size} vs #{bsize}" unless data.size % bsize == 0
            cipher = oracle.call(data)
            #puts "[+] Encrypting for i=#{i} (size (#{data.size}):#{data}"
            #puts "[+] Cipher (size #{cipher.size}): #{cipher.unpack("C*")}"
            acc[cipher[0..prefix.size+plain.size]] = i
            acc
        end
        #puts "[+] are the end uniq ? size #{dic.keys.map{|c| c[prefix.size+1..-1] }.uniq.size}"
        cipher = oracle.call(prefix)
        #puts "[+] cipher #{cipher.unpack("c*")}"
        shortCipher = cipher[0..prefix.size+plain.size]
        #puts "[+] dic[cipher] #{dic[shortCipher]}"
        raise 'whut? no byte found...' if dic[shortCipher].nil?
        dic[shortCipher]
    end

    ## will decrypt the random_pad !
    ## Find the starting length of your dummy data. It must be a multiple length
    #of the block size. Then start by cutting off one byte, call the onebyte
    #lambda to decrypt the missing byte, then cut off one more with the
    #before-last byte being the byte you just discovered.
    result = (1..random_pad.size).inject([]) do |acc,i|
       gibber_size = start_length - i 
       gibber = ("A" * gibber_size).unpack("c*")
       #puts "[+] (#{i}) size #{gibber.size}:\t #{gibber}"
       byte = onebyte.call gibber, acc
       #puts "[+] byte #{i} found: #{byte.chr}"
       acc << byte
    end

    puts "[+] Decrypted unknown:\n #{result.pack("c*")}"
end
