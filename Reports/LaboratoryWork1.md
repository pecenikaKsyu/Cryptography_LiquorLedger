
### Course: Cryptography & Security
### Author: Wu Ksenia-Qin Li 

----

## Cryptography Algorithms 
For centuries, people have come up with ingenious ways to hide information - ciphers, while others have come up with 
even more ingenious ways to reveal information - hacking methods.

In this thread, I want to briefly go through the most famous classical encryption methods and describe the technique 
for cracking each of them.

Encryption is a transformation of the original message that will not allow any bad people to read the data if they 
intercept this message. This transformation is implemented according to dedicated mathematical and logical algorithms, 
some of which we will consider below.

The original message is, in fact, what we want to encrypt. The classic example is text.

An encrypted message is a message that has gone through the encryption process.

The cipher is the algorithm itself according to which we transform the message.

A key is a component that can be used to encrypt or decrypt.

The alphabet is a list of all possible characters in the original and encrypted message, including numbers, punctuation 
marks, spaces, separate uppercase, and lowercase letters, etc.

 ### Caesar Cipher 
The easiest and one of the most famous classical ciphers - the Caesar cipher is perfect for the role of an aperitif.
The Caesar cipher belongs to the group of so-called monoalphabetic substitution ciphers. When using the ciphers of this 
group, each character of the plain text is replaced by other symbol of the same alphabet fixed for a given key.

Keys can be selected in different ways. In the Caesar cipher, the key is an arbitrary number k, chosen in the range 
from 1 to 25. Each letter of the plaintext is replaced by a letter that is k characters further down in the alphabet. 
For example, let the number 3 be the key. Then the letter A of the English alphabet will be replaced by the letter D, 
the letter B by the letter E, and so on.

The small key space (only 25 options) makes brute force the most effective and simpliest attack option.
To open it, you need to replace each letter o f the ciphertext with a letter that is one character to the left in the 
alphabet. If as a result of this it was not possible to obtain a readable message, then it is necessary to repeat the 
action, but already shifting the letters two characters to the left. And so on, until the result is readable text.

 ### Caesar w/ permutation Cipher

This encryption system, along with the numeric key K, which specifies an offset, uses a keyword to change the order of 
characters in the replacement alphabet.

As a keyword, you must select a word or a short phrase (no more than the length of the alphabet). All letters of the 
keyword must be distinct.

To create a replacement array the keyword is written under the letters of the alphabet, starting with the letter whose 
numeric code matches the selected numeric key K. The remaining letters of the replacement alphabet are written in 
alphabetical order (avoiding repetition of letters) after the keyword. When the end of the table is reached, we 
cyclically go to its beginning and add the last letters of the alphabet that have not been seen before.

 ### Playfair Cipher
The Playfair cipher is a substitution cipher that implements the substitution of bigrams. Encryption requires a key, 
which is a table of letters sized 5 * 5 (without the letter J).

The encryption process is reduced to searching for the bigram in the table, and replacing it with a pair of letters 
that form a rectangle with the original bigram.
Consider, as an example, the following table, which forms the key of the Playfair cipher:

|   W   |   H   |   E   |   A   |   T   |
|:-----:|:-----:|:-----:|:-----:|:-----:|
|   S   |   O   |   N   |   B   |   C   |
|   D   |   F   |   G   |   I   |   K   |
|   L   |   M   |   P   |   Q   |   R   |
|   U   |   V   |   X   |   Y   |   Z   |

Let's encrypt the 'WN' pair. The letter W is located in the first row and first column. And the letter N is in the 
second row and third column. These letters form a rectangle with W-E-S-N corners. Therefore, during encryption, the WN 
bigram is converted into the ES bigram.
If the letters are located in one line or column, the result of encryption is a bigram located one position to the 
right/below. For example, bigram NG is converted to bigram GP.

### Vigenere Cipher 

The Vigenère cipher belongs to the group of polyalphabetic substitution ciphers. This means that, depending on the key, 
the same plaintext letter can be encrypted into different characters. This encryption technique hides all the 
frequency characteristics of the text and makes cryptanalysis difficult.

The Vigenère cipher is a sequence of several Caesar ciphers with different keys.

The first task in cryptanalysis of the Vigenère cipher is to find the length of the key used in encryption.

To do this, you can use the match index.

A coincidence index is a number that characterizes the probability that two randomly selected letters from the text 
will be the same.

## Objectives:

1. Get familiar with the basics of cryptography and classical ciphers.

2. Implement 4 types of the classical ciphers:

* Caesar cipher with one key used for substitution (as explained above),
* Caesar cipher with one key used for substitution, and a permutation of the alphabet,
* Vigenere cipher,
* Playfair cipher.
* If you want you can implement other.

## Implementation description
 
Each file contains the code that implements a certain cipher. There are 2 main functions: encryption and decryption for 
each of the ciphers mentioned and described above.

### Classical Caesar Cipher

The program id created to understand 3 types of actions: Encrypt and Decrypt. In lines 5-10 the data for running the 
cipher are read by the code. The variable "end_program" is used to determine whether the en/de-coding is done or it 
should go on.

The encryption is implemented by substitution of each character, one by one, adding the key to the index 
in the alphabet array created. 
```python
        for i in range(len(MyText)):
            if MyText[i] == ' ':
                MyText[i] = ' '
            else:
                new_letter = alphabets.index(MyText[i]) + key
                MyText[i] = alphabets[new_letter]
        print(''.join(map(str, MyText)))
        end_program = True
```

The decryption is executed similarly, decreasing the index by the key. 
```python
        for i in range(len(MyText)):
            if MyText[i] == ' ':
                MyText[i] = ' '
            else:
                new_letter = alphabets.index(MyText[i]) - key
                MyText[i] = alphabets[new_letter]
        print(''.join(map(str, MyText)))
        end_program = True
```

### Caesar with Permutation Cipher 

The lines 1-12 take the input that decides the process to be done, the text and key for the action. The methods Remove 
and Insert are used for permutation the initial alphabet.
```python
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
```
We remove the letters that were used by the keyword and insert it to a new alphabet. Then the encryption/decryption is
implemented according to the Classical Caesar algorithm. Finally, the output is printed. 

```python
def encryptDecrypt(mode, message, key, final=""):
    alpha = insert(remove(Alphabet, stringKey))
    for symbol in message:
        if mode == 'E':
            final += alpha[(alpha.index(symbol) + key) % 26]
        else:
            final += alpha[(alpha.index(symbol) - key) % 26]
    return final
```

### Vigenere Cipher 

The program is created to understand 3 types of actions: Encrypt, Decrypt and Exit. In the driver code the data for 
running the cipher are read. The code is running until the process Exit is called, that means the user could keep
manipulating his/her data in one cycle. The plain text is converted according to the key. The key is a word, that means 
the basic keys in Caesar cipher by their index in alphabet. The digits are kept plain in both cases, they do not need any 
manipulations in this cipher. There are 2 methods that describe the encryption and decryption algorithms. 
```python
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

```
The counter keeps the progress of the process. Each step uses the key, and effectuates the classical caesar cipher 
algorithm to en/de-crypt the letter. When the process is done, the result is printed between 2 rows of stars, and the 
next decision for process is given. 

### Playfair Cipher

The program is created to understand 3 types of actions: Encrypt, Decrypt and Exit. 
```python
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
```
In the driver code (138-149) the data for running the cipher are read. The code is running until the process Exit is 
called, that means the user could keep manipulating his/her data in one cycle. The message is manipulated according to 
the algorithm described above.  
There are 2 methods that are called in the driver code, Encrypt adn Decrypt.
```python
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
```
The table is 5x5 is created according to the keyword (the characters should not repeat). 
```python
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
```
Then using matrix relations the pairs of message text are modified if they correspond to the conditions of the 
cipher(pair is not of same letter, each letter has a pair, if not completed by a more rare character, in our case 'x').
```python
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
```
When the process of EN/DE-cryption is finished the result is printed and a new choice is given.

## Conclusions / Screenshots / Results
In this laboratory work, we studied the most known ciphers. But progress does not stand still. Now you can please
even the most sophisticated client using any of the newer ciphers created by the human mind.