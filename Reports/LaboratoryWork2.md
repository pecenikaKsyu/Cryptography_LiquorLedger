
### Course: Cryptography & Security
### Author: Wu Ksenia-Qin Li 

----

## Cryptography Algorithms
 ### RC4  
In cryptography, RC4 (short for Rivest Cipher 4) is a stream cipher with a variable key length. It uses the same key 
for both encryption and decryption, so it also belongs to the symmetric encryption algorithm. RC4 is the encryption 
algorithm used in Wired Equivalent Encryption (WEP) and was once one of the algorithms that TLS could use.
 
The RC4 serial cipher is a serial cipher developed by the American company RSA Data Security. The company did not 
announce the design details of the RC4 algorithm at the outset. After people got the algorithm through reverse analysis,
RSA announced the RC4 encryption algorithm in 1997.

The advantage of the RC4 algorithm is that the algorithm is simple, efficient, and suitable for software implementation.

RC4 encryption and decryption are equivalent to an involution operation, so if the input keys are the same, encryption 
and decryption of the data is performed by the same actions.

And RC4 is different from the case-based serial cipher. It is a serial cipher based on the transformation of a table of 
non-linear data. It is based on a data table large enough to make non-linear changes to the table. , resulting in a 
non-linear key sequence.

The main process looks like this:

First, RC4 takes a 256-byte table S and introduces a 256-byte auxiliary table R

1. Fill table S linearly
means initialize table S, on the other hand, S[n] = n; (0 <= n <= 255)
2. Populate table R. with the initial value key. If the length of the seed value key is less than the length of the R 
table (256), repeat the filling sequence until the R table is full.
 -In fact, the disadvantages of sequence repopulation are very obvious: For example user enters key a then all a into 
table R after refilling, and the user enters the key aa, then the R table after refilling becomes all a. This is 
clearly not a good result. 
Another way is padding, i.e. if the length of the key is less than the length of the R table, padding in a fixed format 
is used to pad the remainder. 
3. Shuffle list S with list R

The algorithm of work is the following:

①J=0；

②For I=0:255

J = J + S[i] + R[j] mod 256;

swap(S[i], S[j]); // Swap S[i] and S[j]

4. Basic functions of encryption and decryption
After generating a randomized S-table, you can perform data encryption or decryption algorithms.
RC4 can be thought of as a finite state machine during encryption and decryption that generates key bytes by 
continuously generating new states.

The following RC4 state function is defined as follows:

①I=0, J=0; // initialization state

②I = I + 1 mod 256；

③J = J + S[i] mod 256

ap swap(S[i], S[j]); // swap S[i] and S[j]

And the RC4 output function is defined as:

①h = S[i] + S[j] mod 256;

②k = S[h];

The output k of the output function is the generated key byte. Let the final state RC4 automata run one after the other 
to output a sequence of key bytes.

 ### RC5 

RC5 is a block filter with a large number of parameters: block size, key size, and number of stages. It was invented
by Ron Rivest and analyzed at RSA Laboratories [1324, 1325].

Three actions are used: XOR, addition and cyclic shifts. On most processors, cyclic shift operations are performed in 
constant time; variable cyclic shifts are a non-linear function. These cyclic shifts, which depend on both the key and 
the data, are an interesting operation.

RC5 uses a variable length block. The encryption uses 2r+2 key-dependent 32-bit words - S0, S1, S2, ... S2r+1 - where 
r is the number of rounds. We will generate these words later. To encrypt, we first divide the plaintext block into two 
32-bit words: A and B. (RC5 assumes the following convention for packing bytes into words: the first byte occupies the 
low bits of register A, etc.) Then:

A = A + S_0

B = B + S_1

For i = 1 to r:

A = ((A A B) <<< B) + S_(2i)

B = ((B A A) <<< A) + S_(2i+1)

The result is in registers A and B.

Decryption is also easy. Break the plaintext block into two words, A and B, and then:

For i = r down to 1:

B = ((B - S_(2i+1)) >>> A) A A

A = ((A - S_(2i)) >>> B) A B

B = B - S_1

A = A - S_0

The symbol ">>>" denotes a circular shift to the right. Of course, all additions and subtractions are done modulo 2^32.

Creating an array of keys is more complicated, but also straight forward. First, the key bytes are copied into an array 
L of c 32-bit words, padding the final word with zeros if necessary. The array S is then initialized with a linear 
congruential generator modulo 2^32:

S_0 = P

for i = 1 to 2(r + 1) - 1:

S_i = (S_(i-1) + Q) mod 2^32

P = 0xb7e15163 

Q = 0x9e3779b9, these constants are based on the binary representation of e and phi.

Finally, we substitute L into S:

i = j = 0

A = B = 0

execute n times (where n is maximum 2(r + 1) and c):

A = S_i = (S_i + A + B) <<< 3

B = L_i = (L_i + A + B) <<< (A + B)

i = (i + 1) mod 2(r + 1)

j = (j + 1 ) mod c

## Objectives:

1. Get familiar with the symmetric cryptography, stream and block ciphers.
2. Implement an example of a stream cipher.
3. Implement an example of a block cipher.

## Implementation description
 
Each file contains the code that implements a certain cipher. There are 2 main functions: encryption and decryption for 
each of the ciphers mentioned and described above.

### RC5 Block Cipher
For the implementation, initially the initialization of data are needed, that is effectuated by the function __init__ .
```python
    def __init__(self, key):
        self.mode = 'CBC'  # "ECB" or "CBC"
        self.blocksize = 32
        self.rounds = 12
        self.iv = os.urandom(self.blocksize // 8)
        self._key = key.encode('utf-8')
```

The most difficult part is to modify the key to our needs. The algorithm contains 3 steps, aling the key, extend it and 
shuffle it.  This algorithm is implemented by the function _expand_key: 
* align : _align_key
```python
    def _align_key(key, align_val):
                while len(key) % (align_val):
                    key += b'\x00'
                L = []
                for i in range(0, len(key), align_val):
                    L.append(int.from_bytes(key[i:i + align_val], byteorder='little'))
                return L

```
* extend : _extend_key
```python
    def _extend_key(w, r):
               P, Q = _const(w)
               S = [P]
               t = 2 * (r + 1)
               for i in range(1, t):
                   S.append((S[i - 1] + Q) % 2 ** w)
               return S
```
* shuffle : _mix
```python
   def _mix(L, S, r, w, c):
               t = 2 * (r + 1)
               m = max(c, t)
               A = B = i = j = 0
               for k in range(3 * m):
                   A = S[i] = RC5._shift_l(S[i] + A + B, 3, w)
                   B = L[j] = RC5._shift_l(L[j] + A + B, A + B, w)
                   i = (i + 1) % t
                   j = (j + 1) % c
               return S
```

The en/de-coding functions are the next described: _encrypt_block, encrypt_file and encrypt_str,
for encryption,
```python
    def _encrypt_block(data, expanded_key, blocksize, rounds):
        w = blocksize // 2
        b = blocksize // 8
        mod = 2 ** w
        A = int.from_bytes(data[:b // 2], byteorder='little')
        B = int.from_bytes(data[b // 2:], byteorder='little')
        A = (A + expanded_key[0]) % mod
        B = (B + expanded_key[1]) % mod
        for i in range(1, rounds + 1):
            A = (RC5._shift_l((A ^ B), B, w) + expanded_key[2 * i]) % mod
            B = (RC5._shift_l((A ^ B), A, w) + expanded_key[2 * i + 1]) % mod
        res = A.to_bytes(b // 2, byteorder='little') + B.to_bytes(b // 2, byteorder='little')
        return res

    def encrypt_file(self, infile, outfile):
        w = self.blocksize // 2
        b = self.blocksize // 8
        if self.mode == 'CBC':
            last_v = self.iv
            outfile.write(last_v)
        expanded_key = RC5._expand_key(self._key, w, self.rounds)
        chunk = infile.read(b)
        while chunk:
            chunk = chunk.ljust(b, b'\x00')
            if self.mode == 'CBC':
                chunk = bytes([a ^ b for a, b in zip(last_v, chunk)])
            encrypted_chunk = RC5._encrypt_block(chunk, expanded_key,
                                                 self.blocksize,
                                                 self.rounds)
            outfile.write(encrypted_chunk)
            last_v = encrypted_chunk
            chunk = infile.read(b)
            
    def encrypt_str(self, input_str):
        str_in = BytesIO()
        str_in.write(input_str.encode('utf-8'))
        str_in.seek(0)
        str_out = BytesIO()
        self.encrypt_file(str_in, str_out)
        return base64.urlsafe_b64encode(str_out.getvalue()).decode("utf-8")
```
and respectively for the decryption, _decrypt_block, decrypt_file and decrypt_str. 

The driver code runs the cipher, gets the information, encrypts and decrypts the data. 

### RC4 Stream Cipher 

The tricky part in this algorithm is the key. The Key-Scheduling Algorithm is described by the function KSA.
```python
    def KSA(key):
        key_length = len(key)
        S = list(range(MOD))
        j = 0
        for i in range(MOD):
            j = (j + S[i] + key[i % key_length]) % MOD
            S[i], S[j] = S[j], S[i]  # swap values
        return S
```
Pseudo random generation algorithm for stream generation is described by the function PRGA, once the vector S is 
initialized, the input key will not be used. In this step, for each S[i] algorithm swap it with another byte in S according to a 
scheme dictated by the current configuration of S. After reaching S[255] the process continues, starting from S[0] 
again. 
```python
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
```
This algorithm is implemented by the _get_keystream_ function.
```python
    def get_keystream(key):
        S = KSA(key)
        return PRGA(S)
```

The encryption algorithm is based on XOR operation, that is described by the encrypt_logic function.
```python
    def encrypt_logic(key, text):
        key = [ord(c) for c in key]
        stream_key = get_keystream(key)
        res = []
        for c in text:
            val = ("%02X" % (c ^ next(stream_key)))  # XOR and taking hex
            res.append(val)
        return ''.join(res)
```
To encrypt or decrypt the given text called by the "encrypt" and "decrypt" functions.
```python
    def encrypt(key, plain):
        plain = [ord(c) for c in plain]
        return encrypt_logic(key, plain)
    
    def decrypt(key, cipher):
        cipher = codecs.decode(cipher, 'hex_codec')
        res = encrypt_logic(key, cipher)
        return codecs.decode(res, 'hex_codec').decode('utf-8')
    ```

## Conclusions / Screenshots / Results
In this laboratory work, we studied block and stream ciphers. Their implementation is closely related to mathematical 
concepts for encryption or decryption to be effectuated.  

The ideal option in terms of security for the RC4 stream cipher is a key size comparable to the size of the encrypted 
data. Each bit of the plaintext is then combined with the corresponding bit of the key via modulo 2 summation (XOR), 
forming an encrypted sequence. To decrypt, you need to do the same operation again on the receiving side.

RC5 is a new algorithm, but RSA Laboratories has spent a lot of time analyzing how it works with a 64-bit block. After 
5 stages, the statistics look very good. After 8 rounds, each bit of the plaintext affects at least one cyclic shift. 
Differential attack requires 2^24 chosen plaintexts for 5 rounds, 2^45 for 10 rounds, 2^53 for 12 rounds, and 2^68 for 
15 rounds. Of course, there are only 2^64 possible plaintexts, so this attack is not applicable against an algorithm 
with 15 or more rounds. The score for linear cryptanalysis shows that the algorithm is secure after 6 rounds. Rivest 
recommends using at least 12 steps, preferably 16 [1325]. This number may change.
