from crypto_utils import *
import string
from random import randint


class Cipher():
    def __init__(self, alphabet=[chr(i) for i in range(32, 127)]):
        self.alpha_list = alphabet
        self.alpha_len = len(self.alpha_list)
        self.alpha_dict = {self.alpha_list[i]: i for i in range(self.alpha_len)}

    def __str__(self):
        return self.__class__.__name__

    def verify(self, message, encode_key, decode_key):
        encoded = self.encode(message, encode_key)
        decoded = self.decode(encoded, decode_key)
        return message == decoded

    def encode(self, message, encode_key):
        raise NotImplementedError

    def decode(self, encoded_message, decode_key):
        raise NotImplementedError

    def generate_keys(self):
        raise NotImplementedError

class Ceasar(Cipher):
    def encode(self, message, encode_key):
        encoded_message = ""
        for c in message:
            encoded_message += self.alpha_list[(self.alpha_dict[c] + encode_key) % self.alpha_len]
        return encoded_message

    def decode(self, encoded_message, decode_key):
        return self.encode(encoded_message, decode_key)

    def generate_keys(self):
        en_key = randint(0, self.alpha_len - 1)
        return en_key, self.alpha_len - en_key

class Multiplicative(Cipher):
    def encode(self, message, encode_key):
        encoded_message = ""
        for c in message:
            encoded_message += self.alpha_list[(self.alpha_dict[c] * encode_key) % self.alpha_len]
        return encoded_message

    def decode(self, encoded_message, decode_key):
        return self.encode(encoded_message, decode_key)

    def generate_keys(self):
        de_key = None
        while de_key is None:
            en_key = randint(0, self.alpha_len - 1)
            de_key = modular_inverse(en_key, self.alpha_len)
        return en_key, de_key

class Affine(Cipher):
    def __init__(self):
        super().__init__()
        self.multi = Multiplicative()
        self.ceasar = Ceasar()

    def encode(self, message, encode_keys):
        key1, key2 = encode_keys
        return self.ceasar.encode(self.multi.encode(message, key1), key2)

    def decode(self, encoded_message, decode_keys):
        key1, key2 = decode_keys
        return self.multi.decode(self.ceasar.encode(encoded_message, key2), key1)

    def generate_keys(self):
        en_key1, de_key1 = self.multi.generate_keys()
        en_key2, de_key2 = self.ceasar.generate_keys()
        return (en_key1, en_key2), (de_key1, de_key2)

class Unbreakable(Cipher):
    def encode(self, message, encode_key):
        encoded_message = ""
        for i in range(len(message)):
            encoded_message += self.alpha_list[(self.alpha_dict[message[i]] + self.alpha_dict[encode_key[i % len(encode_key)]]) % self.alpha_len]
        return encoded_message

    def decode(self, encoded_message, decode_key):
        return self.encode(encoded_message, decode_key)

    def generate_keys(self):
        word_len = randint(2, 10)
        en_key, de_key = "", ""
        for _ in range(word_len):
            val = randint(0, self.alpha_len - 1)
            en_key += self.alpha_list[val]
            de_key += self.alpha_list[(self.alpha_len - val) % self.alpha_len]
        return en_key, de_key

class RSA(Cipher):
    breakable = False
    substitution = False
    no_bits = 256
    BLOCK_SIZE = 10

    def __init__(self):
        self.__my_generated_decoding_key = None
        self.__my_generated_encoding_key = None
        # Verification of internal data
        if 4 * self.BLOCK_SIZE > self.no_bits:
            print("Block-size %d does not play well with no_bits=%d. no_bits increased to %d" %
                  (self.BLOCK_SIZE, self.no_bits, self.BLOCK_SIZE * 4))
            self.no_bits = 4 * self.BLOCK_SIZE

    def generate_key(self):
        # Generate keys
        p = generate_random_prime(self.no_bits)
        q = generate_random_prime(self.no_bits)

        while p == q:
            # Don't want them to be equal
            q = generate_random_prime(self.no_bits)
        n = p * q
        phi = (p - 1) * (q - 1)

        e = None
        while True:
            e = random.randint(3, phi - 1)
            if math.gcd(e, phi) == 1:
                break  # We are done; there exists a modular inverse for e wrt (p-1) * (q-1)
        d = modular_inverse(e, phi)

        # Store them privately. Needed for later
        self.__my_generated_decoding_key = (n, d)
        self.__my_generated_encoding_key = (n, e)
        return self.__my_generated_decoding_key

    def translate_key(self, receiver_key):
        assert(receiver_key == self.__my_generated_decoding_key)
        return self.__my_generated_encoding_key

    def encode(self, text, key):
        _blocks = []
        for block in blocks_from_text(text, self.BLOCK_SIZE):
            _blocks.append(pow(block, key[1], key[0]))
        return _blocks

    def decode(self, text, key):
        _blocks = []
        for block in text:
            _blocks.append(pow(block, key[1], key[0]))
        return text_from_blocks(_blocks, self.no_bits)
