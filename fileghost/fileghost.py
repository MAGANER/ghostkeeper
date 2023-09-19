import json
import os
import secrets
import sys
from tqdm import tqdm


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

    @classmethod
    def from_file(cls, path: str) -> "keygen":
        '''
        Loads a keygen object from a file.
        '''
        with open(path, "r") as f:
            keys = json.loads(f.read())

        return cls(list(keys.values()))

    def __init__(self, keys: list) -> None:
        if set(keys) != set(range(256)):
            raise ValueError("Keystore must contain all numbers from 0 to 255")

        self._keys = keys
        self._keystore = dict(enumerate(self._keys))

    def to_keystore(self) -> dict:
        return self._keystore.copy()

    def to_byte_array(self) -> list:
        return self._keys.copy()

    def to_hex(self):
        return bytes(self._keys).hex()

    def to_int(self):
        return int(self.to_hex(), 16)

    def to_file(self, path: str) -> None:
        def write_keys() -> None:
            j = json.dumps(self.to_keystore())
            with open(path, "w") as f:
                f.write(j)

            print("Generated new keystore:", path)

        if os.path.exists(path):
            q = input('''This file already exists on specified path. Do you want to replace it?\nBe careful, if you replace it, all the files encrypted with that keystore will be lost forever.\nContinue? [\033[1mY\033[0m/\033[1mN\033[0m] ''')
            if q not in "yY":
                print("Aborted.")
                sys.exit()

        # path doesn't exist OR user wants to replace it
        write_keys()

    def __pan(self, inp: bytes) -> bytes:
        '''if input is too short, then fill it with random bytes'''
        inp = list(inp)
        inp.extend(SEPARATOR)

        while len(inp) < 256:
            inp.append(secrets.randbelow(256))

        return bytes(inp)
    
    def encrypt(self, inp: bytes, disable_input_max_length: bool = False) -> list:
        if not disable_input_max_length and len(inp) > 256:
            print("error: input cannot exceed 256 bytes")
            sys.exit()

        # Input is too short. Extend it with salt and random bytes.
        if len(inp) < 256:
            inp = self.__pan(inp)

        enc_bytes = [self._keystore[n] for n in inp]

        #show progress bar
        for i in tqdm(range(len(enc_bytes))):
            enc_bytes[i] = enc_bytes[i] ^ self._keystore[i % 256]

        return enc_bytes

    def encrypt_file(self, path: str, disable_input_max_length=False) -> list:
        with open(path, "rb") as f:
            return self.encrypt(f.read(), disable_input_max_length)

    def decrypt(self, inp: bytes) -> bytes:
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
