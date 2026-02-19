# RSA 32-bit Implementation and PKCS#1 v1.5 Padding
## Overview
- This project implements a simplified version of the RSA cryptosystem, including:
- A textbook RSA implementation with a 32-bit public modulus
- Key generation using 16-bit prime numbers
- Modular fast exponentiation
- Miller–Rabin primality testing
- Extended Euclidean algorithm for modular inverse
- Encryption and decryption
- An implementation of truncated PKCS#1 v1.5 padding
  
The goal of this project is educational: to understand how RSA works internally, why naive implementations are insecure, and how padding schemes improve security

## How to use ?

`git clone https://github.com/luevard/rsa_32_bit_pkcs-1.git`

`sudo apt update; sudo apt install libssl-dev -y`

`gcc -o rsa main.c -lssl -lcrypto`

`./rsa`

## Demonstrating Factorization Weakness
Since RSA security relies on the difficulty of factoring: 𝑛 = 𝑝×𝑞

Using a 32-bit modulus allows us to clearly observe that:

- Small moduli can be factored quickly
- Security directly depends on key size

This makes the theoretical security assumptions concrete and observable

## Dictionary Attack on Small Messages

If the message space is small (e.g., 1 < m < 100):

1. An attacker can encrypt all possible messages
2. Store them in a dictionary
3. Match ciphertexts to recover the plaintext

With a 32-bit modulus, encrypting all possible small messages takes negligible time, making the attack practical

## Why PKCS#1 v1.5 Padding?

To mitigate these weaknesses, we implemented a truncated version of:

PKCS#1 v1.5 ([RFC 2313](https://www.rfc-editor.org/rfc/rfc2313))

Instead of encrypting the raw message m, we encrypt an Encryption Block (EB):

`EB = BT || PS || 00 || D`

Where:
- BT = Block Type (00, 01, or 02)
- PS = Padding String
- D = Data (message)

In our simplified version:

- The first leading 00 byte is removed
- Message size is 1 byte
- Padding string size is 1 byte

### Security Improvements

PKCS#1 v1.5 improves security because:

#### Randomness (BT = 02)
When padding is random:
- The same message produces different ciphertexts
- Dictionary attacks become ineffective

#### Structured Encoding
During decryption:
- The padding structure must be verified
- Invalid padding can be detected

#### Message Expansion
The plaintext space becomes much larger than the original message space, preventing trivial enumeration attacks
