require "base64"
require "openssl"

module Set2 
    @@bsize = 16
    @@random_key = Random.new.bytes(@@bsize)
    @@random_pad = Base64.decode64 "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    ## random prefix is for ex14. length is chosen subjectively randomly by me.
    @@random_prefix = Random.new.bytes(27)

    ## return aes_ecb using the random_key and padding random_pad to the 
    ## data. data is bytes. If prefix is true, it encrypt prefix + data + suffix for ex14
    def self.oracle data, prefix=false
        cipher = OpenSSL::Cipher.new('AES-128-ECB')
        cipher.encrypt
        cipher.key = @@random_key
        datap = data.pack("c*")
        input = (if prefix then @@random_prefix + datap else datap end ) + @@random_pad
        cipher.update(input) + cipher.final
    end

    ## will compute the dico of encrypting prefix+plain+i with i = (0...256)
    ## prefix = gibberish bytes, plain = the first decrypted bytes
    def self.onebyte prefix,plain,rand_prefix = false
        ## commented because not valid in ex14 since we must add the part that
        #is a the end of the random_prefix until the next block.
        raise "wrong size prefix #{(prefix+plain).size} vs #{@@bsize-1}" unless ((prefix+plain).size% @@bsize) == @@bsize-1
        ## do the dic 
        dic = (0...256).inject({}) do |acc,i|
            data = prefix + plain + [i]
            raise "wrong size data #{data.size} % #{@@bsize} = #{data.size % @@bsize} vs #{@@bsize}" unless data.size % @@bsize == 0
            cipher = Set2.oracle data,rand_prefix 
            #puts "[+] Encrypting for i=#{i} (size (#{data.size}):#{data}"
            #puts "[+] Cipher (size #{cipher.size}): #{cipher.unpack("C*")}"
            acc[cipher[0..prefix.size+plain.size]] = i
            acc
        end
        #puts "[+] are the end uniq ? size #{dic.keys.map{|c| c[prefix.size+1..-1] }.uniq.size}"
        cipher = Set2.oracle prefix,rand_prefix
        #puts "[+] cipher #{cipher.unpack("c*")}"
        shortCipher = cipher[0..prefix.size+plain.size]
        #puts "[+] dic[cipher] #{dic[shortCipher]}"
        #raise 'whut? no byte found...' if dic[shortCipher].nil?
        dic[shortCipher]
    end

    def self.gibberish length
        return ("A" * length).unpack("c*")
    end


    def self.exo14
        puts "[+] Set2 - Ex14"
        ## first thing is to find the prefix size, then it's like exo12 with a
        #different start_length.
        ## Make your input so it stands out in the ciphertext so you know the
        #boundaries between prefix & suffix ==> using ECB is easy you look if
        #two blocks are the same.

        ## detect two equals blocks and returns [[block1,idx1],[block2,idx2]]
        ## or nil if not found
        detect = lambda do |enc|
            ## split by blocksize then takes consecutives blocks
            enc.each_slice(@@bsize).each_with_index.each_cons(2).find { |((a,i),(b,j))| a == b }
        end
        # gen 3 blocks and go down to 2 one by one to find the length
        gibber = ("A" * @@bsize * 3).unpack("C*")  
        # encrypt and record the last index of our 2nd block
        encrypted = (Set2.oracle gibber,true).unpack("C*")
        fblock,sblock = detect.call encrypted
        # index of the second block found with `detect`
        lastBlockIdx = sblock[1]

        i = 1.upto(@@bsize-1).each do |i|
            ## remove one byte per one byte and see if we still have our two
            ## blocks
            smaller = gibber[0..-i]
            enc = Set2.oracle smaller,true
            ## return i unless we still detect two equal blocks
            break i-1 unless detect.call enc.unpack("C*")
        end
        puts "i = #{i}"
        # minus 1 here is because just doing blocksize * rank starts at 1 and
        # not at 0...
        prefix_length = (fblock[1] * @@bsize)-1 - (@@bsize-i)
        raise "wrong length" unless prefix_length == @@random_prefix.size
        full_length = Set2.oracle("".unpack("c*"),true).size
        ## let's get now the length of the part we want to crack,i.e. the suffix
        # get the length of [prefix + pad],[suffix.....]
        # # of bytes to get to the next block after the random_prefix
        padding_prefix = @@bsize - (prefix_length% @@bsize)
        padded_length = Set2.oracle(Set2.gibberish(padding_prefix),true).size
        # now get the suffix length padded
        suffix_length = padded_length - prefix_length - padding_prefix
        # the # of bytes needed to perform the decryption
        start_length = padding_prefix + suffix_length 

        puts "prefix_length #{prefix_length}, suffix_length #{suffix_length} => #{full_length}"
        puts "padding_prefix #{padding_prefix}, start_length = #{start_length}"

        ## will compute the dico of encrypting prefix+plain+i with i = (0...256)
        ## prefix = gibberish bytes, plain = the first decrypted bytes
        onebyte = Proc.new do |prefix,plain|
            ## commented because not valid in ex14 since we must add the part that
            #is a the end of the random_prefix until the next block.
            concat = (prefix + plain).size + prefix_length
            mod = concat % @@bsize
            str = "WRONG: gibberish #{prefix.size}, plain #{plain.size}, prefix_ #{prefix_length} => #{concat}, mod #{mod} vs #{@@bsize-1}" 
            raise str unless mod == @@bsize-1
            ## do the dic 
            dic = (0...256).inject({}) do |acc,i|
                data = prefix + plain + [i]
                concat = data.size + prefix_length
                raise "wrong size data #{concat} % #{@@bsize} = #{concat % @@bsize} vs #{@@bsize}" unless concat % @@bsize == 0
                cipher = Set2.oracle data,true
                #puts "[+] Encrypting for i=#{i} (size (#{data.size}):#{data}"
                #puts "[+] Cipher (size #{cipher.size}): #{cipher.unpack("C*")}"
                acc[cipher[0..prefix_length+prefix.size+plain.size]] = i
                acc
            end
            #puts "[+] are the end uniq ? size #{dic.keys.map{|c| c[prefix.size+1..-1] }.uniq.size}"
            cipher = Set2.oracle prefix,true
            #puts "[+] cipher #{cipher.unpack("c*")}"
            shortCipher = cipher[0..prefix_length+prefix.size+plain.size]
            #puts "[+] dic[cipher] #{dic[shortCipher]}"
            #raise 'whut? no byte found...' if dic[shortCipher].nil?
            dic[shortCipher]
        end

        result = (1...start_length).inject([]) do |acc,i|
            begin
                gibber = Set2.gibberish(start_length - i )
                #puts "[+] (#{i}) size #{gibber.size}:\t" #{gibber}"
                byte = onebyte.call gibber, acc
                #puts "[+] byte #{i} found: #{byte.chr}"
                acc << byte
            rescue Exception => e
                break acc
            end
        end 

        puts "[+] Decrypted unknown:\n #{result.compact.pack("c*")}"

end

def self.exo12
    ## I admit that I will skip the part to determine the block length
    ## and the algo used (cbc vs ecb).
    ## blocklength => call with 1 byte...
    ## algo used => call with two blocks equal
    puts "[+] Set2 - Ex12:"

    ## length of the gibber to place at the beginning. This size is reduced
    #one by one for each byte we find.
    ## One can also compute this by giving the oracle a string of length 0...
    start_length = Set2.oracle("".unpack("c*")).size #@@random_pad.size + (-@@random_pad.size) % @@bsize 

    #puts "[+] random_pad size #{random_pad.size}"
    #puts "[+] gibberish bytes start length #{start_length}"

    ## will decrypt the random_pad !
    ## Find the starting length of your dummy data. It must be a multiple length
    #of the block size. Then start by cutting off one byte, call the onebyte
    #lambda to decrypt the missing byte, then cut off one more with the
    #before-last byte being the byte you just discovered.
    result = (1...start_length).inject([]) do |acc,i|
        begin
            gibber_size = start_length - i 
            gibber = ("A" * gibber_size).unpack("c*")
            #puts "[+] (#{i}) size #{gibber.sizek:\t #{gibber}"
            byte = Set2.onebyte gibber, acc
            #puts "[+] byte #{i} found: #{byte.chr}"
            acc << byte
        rescue Exception => e
            break acc
        end
    end 

    puts "[+] Decrypted unknown:\n #{result.compact.pack("c*")}"
end
def self.exo13

    ## Not really motivated by this exo as it tries to mimic a real world
    ## example but to me that does not sound real at all. no email
    #validation regexp, no encoding enforced. Anyway, here's how I would
    # solve it:
    # ECB Block size = 16 bytes
    # let ECB encrypt something like:
    # |email=blablabla@| |admin(\x11 * 11)| |.co&uid=10&role=| |user|
    # copy paste the second block to the last one, and decrypt.
    # The fact that we dont validate the email with valid alphabetical
    # characters is somewhat really not "real-world". If I were to find a
    # website like, I guess there's much more to be done more easily than to
    # break this crypto. 
    puts "[-] Won't code this one. See comment for solution."
end

end
