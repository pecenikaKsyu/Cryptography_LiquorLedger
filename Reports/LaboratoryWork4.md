
### Course: Cryptography & Security
### Author: Wu Ksenia-Qin Li 

----

## Cryptography Algorithms
 ### RSA -  Rivest, Shamir, Adleman Algorithm

This algorithm was described in the previous laboratory work. a smooth review of the RSA algorithm, the encryption is 
performed: 
* 
* Pick two large primes $p,q$.
* Compute $n=pq$ and $\varphi(n)=\mathrm{lcm}(p-1,q-1)$
* Choose a public key $e$ such that $1< e< \varphi(n)$ and $\gcd(e,\varphi(n))=1$
* Calculate $d$ such that $de\equiv 1 \pmod\varphi(n)$
* Let the message **key** be $m$
* **Encrypt:** $c\equiv m^e\pmod n$
* **Decrypt:** $m\equiv c^d\pmod n$

 ### SHA 256 
SHA-2 (Secure Hash Algorithm), of which the SHA-256 family belongs, is one of the most famous and commonly used hashing
algorithms. SHA-2 is both secure (harder to crack than SHA-1) and fast.

The three main purposes of hash functions are:
* Deterministically encrypt data (this kind of encryption always produces the same encrypted value for the same text 
* value);
* Accept input of any length, and output the result of a fixed length;
* Changing data is irreversible. Input cannot be taken from output.

SHA-2 fulfills them to the fullest. The algorithm for hashing using SHA-256 contains 7 steps, these are described below. 

**Step 1** - Preliminary Work 

This step performs some manipulation with initial data. Initially, the message is converted to binary code, then 
completed by an "1" and "0" until the data is of 448 bits (that is 512-64 bits). Append 64 bits to the end as a 
big-endian integer representing the length of the input message in binary. The result is an input that will be divisible 
by 512 without a remainder.

**Step 2** - Initialize Hash Values (h)

Now 8 hash values are created. These are hard-coded constants that represent the first 32 bits of the fractional parts 
of the square roots of the first eight prime numbers: 2, 3, 5, 7, 11, 13, 17, 19.
```
h0 := 0x6a09e667
h1 := 0xbb67ae85
h2 := 0x3c6ef372
h3 := 0xa54ff53a
h4 := 0x510e527f
h5 := 0x9b05688c
h6 := 0x1f83d9ab
h7 := 0x5be0cd19
```

**Step 3** - Initializing Rounded Constants (k)

As in the previous step, some more constants are created. This time there will be 64. Each value (0-63) represents the 
first 32 bits of the fractional cube roots of the first 64 primes (2-311).

**Step 4** - The Fragment Loop 

The following steps will be performed for each 512-bit "chunk" from our input. In each iteration of the loop,
the hash values ```h0-h7``` are changed, which will lead to the final result.

**Step 5** - Creating a Message Schedule (w)

Copy the input from step 1 into a new array, where each entry is a 32-bit word, Add 48 more words initialized to zero 
to make w[0…63] array. Change the zeroed indexes at the end of the array using the following algorithm:
``` 
For i of w[16…63]:

s0 = (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
s1 = (w[i- 2] rightrotate 17) xor (w[i- 2] rightrotate 19) xor (w[i- 2] rightshift 10)
w[i] = w[i-16] + s0 + w[i-7] + s1
```

**Step 6** - Compression 

Initialize the variables **a, b, c, d, e, f, g, h** and set them to the current values of the hash function **h0, h1, 
h2, h3, h4, h5, h6, h7** respectively.

Run a compression loop that changes the values of **a ... h**. It looks like this:

```
For i from 0 to 63
S1 = (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
ch = (e and f) xor ((not e) and g)
temp1 = h + S1 + ch + k[i] + w[i]
S0 = (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
maj = (a and b) xor (a and c) xor (b and c)
temp2 := S0 + maj
h = g
g = f
e = d + temp1
d=c
c = b
b = a
a = temp1 + temp2
```

**Step 7** - Change the Final Values 

After the compression cycle, during the fragment cycle, the hash values are changed by adding the appropriate **a h** 
variables to them. As before, all addition is done modulo 2^32.

**Step 8** - Final Hash

Finally, everything is put together. 

```
digest = h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
       = B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9
```


## Objectives:

1. Get familiar with the hashing techniques/algorithms.
2. Use an appropriate hashing algorithms to store passwords in a local DB.
* You can use already implemented algortihms from libraries provided for your language.
* The DB choise is up to you, but it can be something simple, like an in memory one.
3. Use an asymmetric cipher to implement a digital signature process for a user message.
* Take the user input message.
* Preprocess the message, if needed.
* Get a digest of it via hashing.
* Encrypt it with the chosen cipher.
* Perform a digital signature check by comparing the hash of the message with the decrypted one.

## Implementation description

### RSA 
 Firstly we import some libraries as SQRT (required for the sqrt() function, to avoid doing **0.5), RANDOM (required
 for randrange and to use the keyword rand), and the hashlib(sha256) . The gcd() function is described in lines 6-10, 
 and calculates the Greatest Common Divisor. This function is used when generating the public key. 
 ```python 
 def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)

 ```
 The next function is calculating the modulo inverse (mod_inverse()), lines 13-17. 
```python 
def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return -1

```

 It is crucial to select 2 prime numbers, unfortunately there is no such a 
 predefined set, thus we create a function that checks it (isprime() 20-29).

```python
def isprime(n):
    if n < 2:
        return False
    elif n == 2:
        return True
    else:
        for i in range(2, int(sqrt(n)) + 1, 2):
            if n % i == 0:
                return False
    return True
```
 
 The function generate_keypair() implements the first steps of the algorithm. Key size is the bit length of n, so it 
 must be in range(nMin,nMax+1). << is bitwise operator. x << y is same as multiplying x by 2**y, This is done so that
 p and q values have similar bit-length, thus, will generate an n value that's hard to factorize into p and q. Two 
 prime numbers in range(start, stop) are chosen so that the difference of bit lengths is at most 2. 56-65 lines 
 describe the selection of prime numbers and determining the number n. In line 67, it is generated public 
 key 1<e<phi(n), and then in line 73, the private key is generated. 
 ```python
e = random.randrange(1, phi)
...
d = mod_inverse(e, phi)
```

 The encrypt function is meant to encrypt the message using the keys generated and using the ord function. Line 85 to
 88, describe the decryption algorithm. There is no need to use ord() since c is now a number. After decryption, we 
 cast it back to character to be joined in a string for the final result.
```python
def encrypt(msg_plaintext, package):
    e, n = package
    msg_ciphertext = [pow(ord(c), e, n) for c in msg_plaintext]
    return msg_ciphertext


def decrypt(msg_ciphertext, package):
    d, n = package
    msg_plaintext = [chr(pow(c, d, n)) for c in msg_ciphertext]
    return (''.join(msg_plaintext))
```

The lines 90-102 are responsible for the hashing functions used in the driver code. 
The _hashFunction_ uses the predefined function extracted from the library imported to encode the initial message. 
The _verify_ function is responsible for checking the correctness of the hashing performed. 
```python
def hashFunction(message):
    hashed = sha256(message.encode("UTF-8")).hexdigest()
    return hashed

def verify(receivedHashed, message):
    ourHashed = hashFunction(message)
    if receivedHashed == ourHashed:
        print("Verification successful: ", )
        print(receivedHashed, " = ", ourHashed)
    else:

        print("Verification failed")
        print(receivedHashed, " != ", ourHashed)
```

 The driver code, 105 to 121, performs the generating operation of the 2 keys: private and public depending on the bit 
 length of the keys, then hashes and encodes the message using the SHA-256 hash algorithm and RSA to encrypt. 

 
 As a result:
 ![](https://github.com/pecenikaKsyu/Cryptography_LiquorLedger/blob/71ee38c54d18d8530c9c5f302f9c97f8a97409ff/lab4/image.png)

## Conclusions / Screenshots / Results
In this laboratory work, we studied hash functions. All functions that are included in this "family"(SHA-2), namely: 
SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/256 and SHA-512/224 are built on the basis of the Merkle-Damgard structure, 
which affects their real resistance to various types of attacks. The principle of operation of absolutely all the above 
algorithms is to split the incoming information into parts of the same size, each of which is processed by the selected 
one-way compression function. The key advantage of this approach is the algorithmic one-sidedness, that is, the 
impossibility of restoring any initial data based on the obtained output result without the presence of a generated key.
This elegant solution was introduced to replace the obsolete SHA-1 by the US National Security Agency in 2002 to more 
securely encrypt sensitive data. One of the most applicable algorithms today is SHA-256, it gained its popularity in 
implementing it into various systems due to such large-scale projects as: Bitcoin and Blockchain . All presented 
functions work safely and are used to this day.