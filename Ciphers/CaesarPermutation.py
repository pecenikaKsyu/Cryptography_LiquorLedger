cryptMode = input("[E]ncrypt|[D]ecrypt:").upper()
if cryptMode not in ['E', 'D']:
    print("Error:")
    raise SystemExit
Alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
startMessage = input('Write your message:').upper()
try:
    numberKey = int(input('Write the number key: '))
except ValueError:
    print("Only numbers!"); raise SystemExit

stringKey = list(input('Write the string key: ').upper())

def remove(alpha, string):
    for symbol in string:
        if symbol not in [chr(x) for x in range(65, 91)] or string.count(symbol) > 1:
            string.remove(symbol)
        if symbol in alpha: alpha.remove(symbol)
    return alpha, string

def insert(alpha_string):
    for index, symbol in enumerate(alpha_string[1]):
        alpha_string[0].insert((numberKey + index) % 26, symbol)
    return alpha_string[0]

def encryptDecrypt(mode, message, key, final=""):
    alpha = insert(remove(Alphabet, stringKey))
    for symbol in message:
        if mode == 'E':
            final += alpha[(alpha.index(symbol) + key) % 26]
        else:
            final += alpha[(alpha.index(symbol) - key) % 26]
    return final

message = encryptDecrypt(cryptMode, startMessage, numberKey)
print("Final", message)