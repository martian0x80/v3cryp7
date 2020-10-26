from Crypto.Cipher import AES
import os
import random
import struct
 
 
def decrypt_file(key, filename, chunk_size=24*1024):
    output_filename = os.path.splitext(filename)[0]
    with open(filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)
        with open(output_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(origsize)
 
 
def encrypt_file(key, filename, chunk_size=64*1024):
    output_filename = filename + '.encrypted'
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(filename)
    with open(filename, 'rb') as inputfile:
        with open(output_filename, 'wb') as outputfile:
            outputfile.write(struct.pack('<Q', filesize))
            outputfile.write(iv)
            while True:
                chunk = inputfile.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)
                outputfile.write(encryptor.encrypt(chunk))
 
 
##
# Example usage:
##
 
# Encrypt file:
encrypt_file('abcdefghji123456', 'sample-file.txt')
 
# Decrypt file:
decrypt_file('abcdefghji123456', 'sample-file.txt.encrypted')