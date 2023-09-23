# Ghostkeeper
XOR encryption implemented in python: Fork( it should be used in serious project, since XOR encryption isn't tough enough. Project was forked for fun and research)

Usage:
```
key = fg.keygen.generate() #create key and object to encrypt data
encrypted_message = key.encrypt(byte_message)
decrypted_message = key.decrypt(encrypted_message)
print(decrypted_message) # shows decrypted string with bytes

#print(key.to_hex())  # you can show key as hex
```
