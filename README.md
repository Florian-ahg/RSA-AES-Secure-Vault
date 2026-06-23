# MY_PGP — A Song of Ciphers and Primes

A from-scratch implementation of a **PGP-like cryptosystem** in C++, combining
symmetric and asymmetric cryptography to securely exchange messages over an
untrusted channel.

Every algorithm (XOR, AES-128, RSA) is implemented **by hand** — no crypto
library is used for the ciphers themselves. Only [GMP](https://gmplib.org/) is
used, for arbitrary-precision integer arithmetic in RSA.

> Epitech project `G-CNA-500` — the full subject is available in
> [`docs/`](docs/).

---

## Why this project is interesting

Public-key cryptography (RSA) solves key exchange but is too slow for long
messages. Symmetric cryptography (AES) is fast but requires a shared secret.
**PGP combines both**: a random symmetric key encrypts the message, and the
recipient's public key encrypts that symmetric key. This project rebuilds that
whole pipeline end to end.

```
                ┌─────────────┐
  message  ───► │  AES / XOR  │ ───►  encrypted message
                └─────────────┘
                      ▲
              random symmetric key
                      │
                ┌─────────────┐
                │     RSA      │ ───►  encrypted symmetric key
                └─────────────┘
                      ▲
              recipient public key
```

The recipient reverses the process: RSA (with the private key) recovers the
symmetric key, which then decrypts the message.

---

## Cryptosystems implemented

| System    | Type                  | Description                                   |
|-----------|-----------------------|-----------------------------------------------|
| `xor`     | Symmetric             | Simple XOR with a repeating key               |
| `aes`     | Symmetric             | AES-128 (S-box, ShiftRows, MixColumns, key expansion) |
| `rsa`     | Asymmetric            | Key generation (Carmichael's totient) + cipher/decipher |
| `pgp-xor` | Hybrid (RSA + XOR)    | PGP scheme using XOR as the symmetric cipher  |
| `pgp-aes` | Hybrid (RSA + AES)    | PGP scheme using AES as the symmetric cipher  |

All numbers (RSA keys, ciphertext) are represented in **little-endian**
hexadecimal, as required by the subject.

---

## Build

Requires `g++` (C++17) and the GMP library (`libgmp-dev`).

```bash
make          # build ./my_pgp
make clean    # remove object files
make fclean   # remove object files and the binary
make re       # rebuild from scratch
```

---

## Usage

```
./my_pgp CRYPTO_SYSTEM MODE [OPTIONS] [key]
```

| Argument        | Meaning                                                           |
|-----------------|------------------------------------------------------------------|
| `CRYPTO_SYSTEM` | `xor` \| `aes` \| `rsa` \| `pgp-xor` \| `pgp-aes`                 |
| `-c`            | Cipher the message (read from stdin)                             |
| `-d`            | Decipher the message (read from stdin)                          |
| `-g P Q`        | RSA only: generate a key pair from prime numbers `P` and `Q`     |
| `-b`            | Block mode: process a single block (message and key same size)   |
| `key`           | Key used to cipher/decipher                                       |

Without `-b`, ciphers run in **stream mode** (any message length; the last AES
block is zero-padded).

### Examples

**XOR**
```bash
echo "You know nothing, Jon Snow" | ./my_pgp xor -c 5768617420646f2077652073617920746f2074686520476f64206f662044656174
```

**AES-128**
```bash
echo "All men must die" | ./my_pgp aes -c -b 57696e74657266656c6c206973206364
```

**RSA — generate keys, then cipher/decipher**
```bash
./my_pgp rsa -g d3 e3
# public key: 0101-19bb
# private key: 9d5b-19bb

echo "WF" | ./my_pgp rsa -c 0101-19bb   # -> 8f84
echo "8f84" | ./my_pgp rsa -d 9d5b-19bb # -> WF
```

**PGP (AES + RSA)** — the key is given as `SYMMETRIC_KEY:RSA_KEY`. The first
output line is the RSA-encrypted symmetric key, the second is the encrypted
message.
```bash
echo "Winter is coming" | ./my_pgp pgp-aes -c "000102030405060708090a0b0c0d0e0f:<public_key>"
```

On error, the program writes to stderr and exits with code **84**.

---

## Project structure

```
.
├── include/        # Headers (AES, RSA, Options, conversions)
├── src/
│   ├── main.cpp            # Argument parsing & dispatch
│   ├── AES.cpp             # AES-128 implementation
│   ├── RSA.cpp             # RSA + little-endian/GMP conversions
│   ├── xor.cpp             # XOR cipher
│   ├── convert.cpp         # hex<->bytes, I/O, AES driver
│   ├── handle_pgp_aes.cpp  # RSA + AES hybrid
│   └── handle_pgp_xor.cpp  # RSA + XOR hybrid
├── docs/           # Project subject & presentation (PDF)
└── Makefile
```

---

## Notes & limitations

- The public exponent `e` is chosen as the largest Fermat prime coprime with
  Carmichael's totient `λ(n)`.
- AES stream mode uses **zero-padding**: a decrypted message may carry trailing
  null bytes if the original length was not a multiple of 16.
- This is an educational implementation — it is **not** meant for real-world
  security use.
