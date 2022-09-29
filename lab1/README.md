
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

 ###Caesar Cipher 
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

 ###Caesar w/ permutation Cipher

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

## Conclusions / Screenshots / Results
In this laboratory work, we studied the most known ciphers. But progress does not stand still. Now you can please
even the most sophisticated client using any of the newer ciphers created by the human mind.