import json
import os
import secrets
import random
import sys
import hashlib
from functools import reduce
from tqdm import tqdm



#use it to fill empty space
SEP = '__FIL3GH0ST__'.encode()
SEPARATOR = list(bytes(SEP))


class keygen:
    @classmethod
    def generate(cls) -> "keygen":
        '''
        Generates a new keygen object with random keys, based on the ``secrets`` module.
        '''
        keys = []

        #generate unique numbers
        numbers = set()
        while len(numbers) < 256:
            n = secrets.randbelow(256)

            if n not in numbers:
                numbers.add(n)
                keys.append(n)

        return cls(keys)

    def __init__(self, keys: list) -> None:
        if set(keys) != set(range(256)):
            raise ValueError("Keystore must contain all numbers from 0 to 255")

        self._keys = keys
        self._keystore = dict(enumerate(self._keys))
        
    def to_hex(self):
        return bytes(self._keys).hex()
        
    def __pan(self, inp: bytes) -> bytes:
        '''if input is too short, then fill it with random bytes'''
        inp = list(inp)
        inp.extend(SEPARATOR)

        while len(inp) < 256:
            inp.append(secrets.randbelow(256))

        return bytes(inp)
    def __chunks(self,lst, n):
        """Yield successive n-sized chunks from lst."""
        for i in range(0, len(lst), n):
            yield lst[i:i + n]


    def encrypt(self, inp: bytes) -> bytes:
        '''split input message -> encrypt every chunk -> concatenate encrypted chunks'''
        encrypted_chunks = [self.__encrypt_chunk(chunk) for chunk in self.__chunks(inp,256)]
        return bytes(reduce(lambda a,b: a+b, encrypted_chunks))
    def __encrypt_chunk(self, inp: bytes) -> list:
        '''encrypt message which size is less than 256(if it's less than 256 message will be filled with salt'''
        
        # Input is too short. Extend it with salt and random bytes.
        if len(inp) < 256:
            inp = self.__pan(inp)

        enc_bytes = [self._keystore[n] for n in inp]

        #show progress bar
        for i in tqdm(range(len(enc_bytes))):
            enc_bytes[i] = enc_bytes[i] ^ self._keystore[i % 256]

        return enc_bytes

    def encrypt_file(self, path: str) -> list:
        with open(path, "rb") as f:
            return self.encrypt(f.read())


    def decrypt(self, inp:bytes) -> bytes:
        decrypted_chunks = [self.__decrypt_chunk(chunk) for chunk in self.__chunks(inp,256)]
        return bytes(reduce(lambda a,b: a+b,decrypted_chunks))
    def __decrypt_chunk(self, inp: bytes) -> bytes:
        inp = list(inp)
        for i in range(len(inp)):
            inp[i] = inp[i] ^ self._keystore[i % 256]

        decr_bytes = []
        indices = list(range(256))

        for b in tqdm(inp):
            assert 0 <= b <= 255
            decr_bytes.append(indices[self._keys.index(b)])

        decr_bytes=bytes(decr_bytes)

        sep_iloc = decr_bytes.find(SEP)
        if sep_iloc != -1:
            decr_bytes=decr_bytes[:decr_bytes.find(SEP)]
        return decr_bytes

    def decrypt_file(self, path: str) -> bytes:
        with open(path, "rb") as f:
            return self.decrypt(f.read())
