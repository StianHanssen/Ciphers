class Person():
    def __init__(self, key=None, cipher=None):
        self.key = key
        self.cipher = cipher

    def set_key(self, key):
        self.key = key

    def get_key(self):
        return self.key

    def set_cipher(self, cipher):
        self.cipher = cipher

    def get_cipher(self):
        return self.cipher

    def operate_cipher(self, message):
        raise NotImplementedError

class Sender(Person):
    def operate_cipher(self, message):
        return self.cipher.encode(message, self.key)

class Receiver(Person):
    def operate_cipher(self, message):
        return self.cipher.decode(message, self.key)

class Hacker(Person):
    def __init__(self, cipher):
        super().__init__(cipher)
        self.key_range = cipher.get_brute_force_keys()

        with open("english_words.txt") as word_file:
            self.english_words = set(word.strip().lower() for word in word_file)

    def is_english_word(self, _word):
        return _word.lower() in self.english_words

    def operate_cipher(self, message):
        if self.cipher.breakable is False:
            best_decode = "ERROR: Cipher is unbreakable, so this won't work"
        else:
            # We have a chance -- so lets try
            best_result, best_key, best_decode = -1, None, None
            for decoding_key in self.key_range:
                decoded_attempt = self.cipher.decode(message, decoding_key)

                # Drop strange/annoying characters
                for noise in '.,!"#$%&/()=1234567890':
                    decoded_attempt = decoded_attempt.replace(noise, ' ')
                current__result = 0
                for token in decoded_attempt.lower().split():
                    if self.is_english_word(token) is True:
                        current__result += 1

                if len(decoded_attempt.split()) > 0:
                    current__result /= len(decoded_attempt.split())
                else:
                    current__result = 0

                if current__result > best_result:
                    best_key, best_result, best_decode = decoding_key, current__result, decoded_attempt

                if best_result == 1:
                    break

        return best_decode
