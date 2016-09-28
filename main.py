from cipher import *
from person import *

if __name__ == "__main__":
    ciphs = [Ceasar(), Multiplicative(), Affine(), Unbreakable()]
    message = "This is some kode! Cool right?"
    send = Sender()
    resiv = Receiver()
    for i in range(len(ciphs)):
        en_key, de_key = ciphs[i].generate_keys()
        send.set_cipher(ciphs[i])
        resiv.set_cipher(ciphs[i])
        send.set_key(en_key)
        resiv.set_key(de_key)
        en_message = send.operate_cipher(message)
        de_message = resiv.operate_cipher(en_message)
        print("Cipher\t\t" + ":", str(ciphs[i]))
        print("Encode Key\t" + ":", en_key)
        print("Decode Key\t" + ":", de_key)
        print("Message\t\t" + ":", message)
        print("Encoded Message\t" + ":", en_message)
        print("Decoded Message\t" + ":", de_message)
        print("Verified\t" + ":", ciphs[i].verify(message, en_key, de_key), "\n")
