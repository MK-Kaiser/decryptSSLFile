#!/usr/bin/env python3
# decrypts openssl encrypted files if the last 30 bytes are \x00, then the first two bytes can be bruteforced

from Crypto.Cipher import AES # import the crypto functionality needed

with open('note.enc','rb') as f: # read the encrypted file; call its data cipher_text
    cipher_text = f.read()

for a in range(0,255): # run 255 times with i of 00, 01, 02...
    plain_text = '' # start with empty string for plaint_text
    # set up decryption with this value of i
    for b in range(0,255):
        plain_text = '' # start with empty string for plaint_text
        # set up decryption with this value of i
        decr = AES.new(bytes.fromhex("{:02x}".format(a)+"{:02x}".format(b)+'00'*30), AES.MODE_CBC, bytes.fromhex('00'*16))
        plain_text = decr.decrypt(cipher_text) # do the decryption
        if (b'stop' in plain_text): 
            print(str(plain_text,'utf8')) # search for "stop" in the result
