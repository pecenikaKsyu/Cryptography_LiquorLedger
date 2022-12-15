
### Course: Cryptography & Security
### Author: Wu Ksenia-Qin Li 

----

## Cryptography Algorithms
 ### RSA -  Rivest, Shamir, Adleman Algorithm

Such encryption is much more difficult than the ciphers studied before.

Let's assume that Alice and Bob work for a company. They need to send a message to each other safely. But unfortunately,
they are forced to send messages to each other through a chatty secretary who loves to read other people's letters. What
should they do? Now they can't just exchange keys.

The solution lies on the surface - it is necessary to send something so that Alice could send her message to Bob without
passing the key. And here mathematics with its prime numbers comes to give a hand.

One of algorithms they could use is the RSA algorithm. Its creators Ronald Lynn Rivest, Adi Shamir, and Leonard Max 
Adleman came up with it, and in August 1977, the first description of the RSA crypto-system appeared in Martin 
Gardner's "Math Games" column in Scientific American. 

So how does it work and why is it so hard to decipher the message? It is due to the fact that asymmetric ciphers use 
the so-called "One-way functions".

**One-Way Functions**

A one-way function is a mathematical function that is easy to evaluate for any input value, but difficult to find the
argument given the value of the function.

As we know from the mathematics course of grades 5-6, any non-prime number can be represented as a product of prime 
factors.

If it is obviously 10=2*5, but what prime factors does the number 12547864874 consist of?

Based on this, we assume that factorization (the decomposition of a number into a product of prime factors) is much 
more complicated than the same multiplication.

To encrypt a message, it is necessary to find two simple and long numbers. 

And, according to the following algorithm the encryption is performed: 
* Pick two large primes $p,q$.
* Compute $n=pq$ and $\varphi(n)=\mathrm{lcm}(p-1,q-1)$
* Choose a public key $e$ such that $1< e< \varphi(n)$ and $\gcd(e,\varphi(n))=1$
* Calculate $d$ such that $de\equiv 1 \pmod\varphi(n)$
* Let the message **key** be $m$
* **Encrypt:** $c\equiv m^e\pmod n$
* **Decrypt:** $m\equiv c^d\pmod n$

## Objectives:

1. Get familiar with the asymmetric cryptography mechanisms
2. Implement an example of asymmetric cipher 


## Implementation description
 
Each file contains the code that implements a certain cipher. There are 2 main functions: encryption and decryption for 
each of the ciphers mentioned and described above.

### RSA 
 Firstly we import some libraries as SQRT (required for the sqrt() function, to avoid doing **0.5), and RANDOM (required
 for randrange and to use the keyword rand). The gcd() function is described in lines 6-10, and calculates the Greatest 
 Common Divisor. This function is used when generating the public key. 
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
 describe the selection of prime numbers and determining the number n. In line 66, it is generated public 
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

 The driver code, 91 to 105, performs the generating operation of the 2 keys: private and public depending on the bit length of the keys. 

 
 As a result:
 ![](https://github.com/pecenikaKsyu/Cryptography_LiquorLedger/blob/8057f157a90a81798f67422524d4a541d0c3d5cb/lab3/results.png)

## Conclusions / Screenshots / Results
In this laboratory work, we studied asymmetric ciphers. There are two main problems with RSA today, one a consequence 
of the other. As the key length grows, the complexity does not grow as fast as we would like. This is because there is
a subexponential (but still superpolynomial) factorization algorithm. Therefore, to maintain the required level of 
protection, the length of the RSA key must grow somewhat faster than that of the ECC key. For this reason, the most 
common RSA key lengths today are quite large: 2048 and 3072 bits.