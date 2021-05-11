#Make sure to have these downloaded and available, they will be imported by the iga module
#https://asecuritysite.com/encryption/ffx
#https://github.com/mjschultz/py-radix

import iga

plainip = "193.0.2.255"
key = b'mytestkey'
iga.setKey(key)

print("Plaintext IP: "+plainip)
enc = iga.rankAndEncrypt(plainip)
print("Encrypted IP: "+enc)
dec = iga.decryptAndDerank(enc)
print("Decrypted IP: "+dec)

print()

plainip = "8.8.8.8"
print("Plaintext IP: "+plainip)
enc = iga.rankAndEncrypt(plainip)
print("Encrypted IP: "+enc)
dec = iga.decryptAndDerank(enc)
print("Decrypted IP: "+dec)
