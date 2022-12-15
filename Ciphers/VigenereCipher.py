def Encryption(plain, num_key):
    count = 0
    cipher = ''
    for i in range(len(plain)):
        char0 = plain[i]
        char = char0.lower()
        if char == " ":
            cipher += ' '
        elif char.isdigit():
            cipher += char
        elif char.isalpha():
            if count < len(num_key):
                key1 = num_key[count]
                cipher += chr((ord(char) + key1 - 97) % 26 + 97)
                count += 1
            if count == len(num_key):
                count = 0
    return cipher

def Decryption(cipher, num_key):
    count = 0
    plain = ''
    for i in range(len(cipher)):
        char0 = cipher[i]
        char = char0.lower()
        if char == " ":
            plain += ' '
        elif char.isdigit():
            plain += char
        elif char.isalpha():
            if count < len(num_key):
                key1 = num_key[count]
                plain += chr((ord(char) - key1 - 97) % 26 + 97)
                count += 1
            if count == len(num_key):
                count = 0
    return plain

if __name__ == "__main__":
    num_key = []
    while True:
        print('[*] Press 1 for Encryption \n[*] Press 0 for Decryption \n[*] Press 01 to exit.. ')
        choice = input('Insert Here : ')
        if choice.isdigit():
            if choice == '1':
                plain = input('Please insert the plaintext : ')
                while True:
                    key0 = input('Please insert the key : ')
                    if len(key0) <= len(plain):
                        if key0.isalpha():
                            key = key0.lower()
                            for i in range(len(key)):
                                key1 = key[i]
                                num_key.append(ord(key1) - 97)
                            break
                    else:
                        print('The length of the key must be lower or equal to the plainext ! \n')
                print('\n')
                print(50 * '*')
                print(f'[*] Ciphertext --> {Encryption(plain, num_key)}')
                print(50 * '*' + '\n')
            elif choice == '0':
                cipher = input('Please insert the ciphertext : ')
                while True:
                    key0 = input('Please insert the key : ')
                    if key0.isalpha():
                        key = key0.lower()
                        for i in range(len(key)):
                            key1 = key[i]
                            num_key.append(ord(key1) - 97)
                        break
                print('\n')
                print(50 * '*')
                print(f'[*] Plaintext --> {Decryption(cipher, num_key)}')
                print(50 * '*' + '\n')
            elif choice == '01':
                print('Exiting..')
                break
            else:
                print('Exception error .. \n'
                      'Please insert : 0|1|01')