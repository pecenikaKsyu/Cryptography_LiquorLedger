### RC4 cipher - a stream cipher

import codecs
MOD = 256
def KSA(key):
    key_length = len(key)
    S = list(range(MOD))
    j = 0
    for i in range(MOD):
        j = (j + S[i] + key[i % key_length]) % MOD
        S[i], S[j] = S[j], S[i]  # swap values
    return S

def PRGA(S):
    #Psudo Random Generation Algorithm
    i = 0
    j = 0
    while True:
        i = (i + 1) % MOD
        j = (j + S[i]) % MOD
        S[i], S[j] = S[j], S[i]  # swap values
        K = S[(S[i] + S[j]) % MOD]
        yield K

def get_keystream(key):
    S = KSA(key)
    return PRGA(S)

def encrypt_logic(key, text):
    key = [ord(c) for c in key]
    stream_key = get_keystream(key)
    res = []
    for c in text:
        val = ("%02X" % (c ^ next(stream_key)))  # XOR and taking hex
        res.append(val)
    return ''.join(res)

def encrypt(key, plain):
    plain = [ord(c) for c in plain]
    return encrypt_logic(key, plain)

def decrypt(key, cipher):
    cipher = codecs.decode(cipher, 'hex_codec')
    res = encrypt_logic(key, cipher)
    return codecs.decode(res, 'hex_codec').decode('utf-8')

if __name__ == '__main__':
    key = input('Introduce the key in plain text: ')
    plain = input('Introduce the plain text to encrypt: ')
    cipher = encrypt(key, plain)
    print('plaintext:', plain)
    print('ciphertext:', cipher)
    decrypted = decrypt(key, cipher)
    print('decrypted:', decrypted)

