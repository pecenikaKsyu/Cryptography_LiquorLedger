import string

letters = string.ascii_letters[0:26]

def encrypt(key):
    dup_letters = list(letters)
    for char in key:
        dup_letters.remove(char)
    dup_letters.remove("j")
    keyLen = len(key)
    letters_length = len(dup_letters)
    keyID = 0
    letterID = 0
    matrix = []
    for i in range(5):
        l = []
        for j in range(5):
            if (keyID < keyLen):
                l.append(key[keyID])
                keyID += 1
            elif (letterID < letters_length):
                l.append(dup_letters[letterID])
                letterID += 1
        matrix.append(l)
    cipher = ""
    plain = input("\nEnter the plain text : ")
    modPlain = "".join(plain.split(" "))
    plainMx = []
    plainID = 0
    while (plainID != len(modPlain)):
        l = []
        l.append(modPlain[plainID])
        plainID += 1
        if (plainID < len(modPlain)):
            if (modPlain[plainID] == l[0]):
                l.append('x')
            else:
                l.append(modPlain[plainID])
                plainID += 1
        plainMx.append(l)
    if (len(plainMx[len(plainMx) - 1]) == 1):
        plainMx[len(plainMx) - 1].append('x')
    chipherID = 0
    while (chipherID != len(plainMx)):
        one = plainMx[chipherID][0]
        two = plainMx[chipherID][1]
        row1 = 0
        col1 = 0
        row2 = 0
        col2 = 0
        for i in range(5):
            for j in range(5):
                if (matrix[i][j] == one):
                    row1 = i
                    col1 = j
                elif (matrix[i][j] == two):
                    row2 = i
                    col2 = j
        if (row1 == row2):
            cipher += matrix[row1][(col1 + 1) % 5]
            cipher += matrix[row2][(col2 + 1) % 5]
        elif (col1 == col2):
            cipher += matrix[(row1 + 1) % 5][col1]
            cipher += matrix[(row2 + 1) % 5][col2]
        else:
            cipher += matrix[row1][col2]
            cipher += matrix[row2][col1]
        chipherID += 1
    print("The Cipher Text is : " + cipher)

def decrypt(key):
    dup_letters = list(letters)
    for char in key:
        dup_letters.remove(char)
    dup_letters.remove("j")
    keyLen = len(key)
    letters_length = len(dup_letters)
    keyID = 0
    letterID = 0
    matrix = []

    for i in range(5):
        l = []
        for j in range(5):
            if (keyID < keyLen):
                l.append(key[keyID])
                keyID += 1
            elif (letterID < letters_length):
                l.append(dup_letters[letterID])
                letterID += 1
        matrix.append(l)
    cipher_text = input("\nEnter the cipher text : ")
    modCipher = "".join(cipher_text.split(" "))
    plain = ""
    cipherMx = []
    cipherId = 0
    while (cipherId != len(modCipher)):
        l = []
        l.append(modCipher[cipherId])
        cipherId += 1
        if (cipherId < len(modCipher)):
            if (modCipher[cipherId] == l[0]):
                l.append('x')
            else:
                l.append(modCipher[cipherId])
                cipherId += 1
        cipherMx.append(l)
    if (len(cipherMx[len(cipherMx) - 1]) == 1):
        cipherMx[len(cipherMx) - 1].append('x')
    plainID = 0
    while (plainID != len(cipherMx)):
        one = cipherMx[plainID][0]
        two = cipherMx[plainID][1]
        row1 = 0
        col1 = 0
        row2 = 0
        col2 = 0
        for i in range(5):
            for j in range(5):
                if (matrix[i][j] == one):
                    row1 = i
                    col1 = j
                elif (matrix[i][j] == two):
                    row2 = i
                    col2 = j
        if (row1 == row2):
            plain += matrix[row1][col1 - 1]
            plain += matrix[row2][col2 - 1]
        elif (col1 == col2):
            plain += matrix[row1 - 1][col1]
            plain += matrix[row2 - 1][col2]
        else:
            plain += matrix[row1][col2]
            plain += matrix[row2][col1]
        plainID += 1
    print("The Plain Text is : " + plain)

choice = 0
key = 0
while (True):
    choice = int(input("\n\n********MENU********\n\n1.Encrypt\n2.Decrypt\n3.Exit\n\nEnter your choice : "))
    if (choice == 1):
        key = input("\nEnter the key : ")
        encrypt(key)
    elif (choice == 2):
        key = input("\nEnter the key : ")
        decrypt(key)
    elif (choice == 3):
        break
