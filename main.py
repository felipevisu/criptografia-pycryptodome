from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

SALT = get_random_bytes(16)

def generate_key(password):
   key = PBKDF2(password, SALT, 64, 1000, hmac_hash_module=SHA256)
   return key


def generate_mac(text, key):
    h = HMAC.new(key, digestmod=SHA256)
    h.update(text)
    return h.hexdigest()


def encrypt(plaintext, password, mode):
    key = generate_key(password)
    key1 = key[:32]
    key2 = key[32:]

    if mode == 'ETM':
        cipher = AES.new(key1, AES.MODE_CBC)
        ciphertext = cipher.iv + cipher.encrypt(pad(plaintext, AES.block_size))
        signature = generate_mac(ciphertext, key2)
        return ciphertext + signature.encode()

    if mode == 'EAM':
        signature = generate_mac(plaintext, key2)
        cipher = AES.new(key1, AES.MODE_CBC)
        ciphertext = cipher.iv + cipher.encrypt(pad(plaintext, AES.block_size))
        return ciphertext + signature.encode()

    if mode == 'MTE':
        signature = generate_mac(plaintext, key2)
        plaintext = plaintext + signature.encode()
        cipher = AES.new(key1, AES.MODE_CBC)
        ciphertext = cipher.iv + cipher.encrypt(pad(plaintext, AES.block_size))
        return ciphertext


def decrypt(ciphertext, password, mode):
    key = generate_key(password)
    key1 = key[:32]
    key2 = key[32:]

    if mode == "ETM":
        signature = ciphertext[-64:]
        ciphertext = ciphertext[:-64]
        mac = generate_mac(ciphertext, key2)
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = AES.new(key1, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode(), mac.encode() == signature

    if mode == "EAM":
        signature = ciphertext[-64:]
        ciphertext = ciphertext[:-64]
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = AES.new(key1, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        mac = generate_mac(plaintext, key2)
        return plaintext.decode(), mac.encode() == signature

    if mode == "MTE":
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = AES.new(key1, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        signature = plaintext[-64:]
        plaintext = plaintext[0:-64]
        mac = generate_mac(plaintext, key2)
        return plaintext.decode(), mac.encode() == signature


if __name__ == '__main__':
    while True:
        text = str(input("Digite um texto ou nome de um arquivo para ser criptografado: "))

        try:
            file = open(text, "rb")
            text = file.read()
        except:
            text = text.encode()

        password = str(input("Digite uma senha: ")).encode()
        mode = input("Digite um modo de encriptação (ETM, EAM ou MTE): ")

        cypertext = encrypt(text, password, mode)
        plaintext, tag = decrypt(cypertext, password, mode)
        
        print("\nTexto encriptado:")
        print(cypertext)

        print("\nTexto decriptado:")
        print(plaintext)

        print("\nTag MAC:", tag)

        print("\nAperte Ctrl-c para sair ou criptografe outro texto.")
        print("\n-----------------------\n")

