# CLI RSA Encryption Tool

A command-line Python tool for RSA encryption and decryption, including key generation and basic cryptanalysis via factorization. This project demonstrates the implementation of RSA from scratch, using standard algorithms like fast modular exponentiation, the Euclidean and Extended Euclidean Algorithms, trial division, and Pollard's Rho factorization.

## 🛠 Features

- Generate RSA public and private keys from two prime numbers.
- Encrypt messages using the RSA public key.
- Decrypt messages using the RSA private key.
- Attempt to break RSA encryption by factorizing the modulus (for educational purposes).
- Interactive command-line menu with ASCII art interface.

## ⚙️ Tech Stack

- Python 3 (single-file implementation)
- Standard Python libraries: `math`, `time`, `random`

## 📚 Implementation Highlights

- **Fast Modular Exponentiation (FME):** Efficiently computes `b^n mod m`.
- **GCD & Extended Euclidean Algorithm (EEA):** Compute coprimality and modular inverses.
- **Prime Validation:** Checks if numbers are prime before key generation.
- **Factorization Methods:** Uses trial division and Pollard's Rho to attempt breaking small RSA keys.
- **ASCII Encoding:** Converts messages to integer lists for encryption and back to text for decryption.

## 🖥 Usage

Run the Python file:

```bash
python rsa_cli.py
````

The interactive menu allows you to:

1. **Generate Keys**: Enter two primes `p` and `q` to generate the public `(n, e)` and private `(n, d)` keys.
2. **Encode Message**: Encrypt a plaintext message with the public key.
3. **Decode Message**: Decrypt a message using the private key.
4. **Break Code**: Attempt to factorize `n` to recover the keys and decrypt a message (educational/demo purposes only).
5. **Exit**: Quit the program.

### Example Workflow

1. Generate keys using small primes:

```
Enter a prime number p: 17
Enter a prime number q: 19
Public Key (n, e): (323, 3)
Private Key (n, d): (323, 235)
```

2. Encode a message:

```
Enter the message to encode: HELLO
Encoded Message: [72, 8, 246, 246, 157]
```

3. Decode the message:

```
Enter the encoded message: [72, 8, 246, 246, 157]
Decoded Message: HELLO
```

4. Break code:

```
Enter the encrypted message: [72, 8, 246, 246, 157]
Enter the modulus n: 323
Enter the public exponent e: 3
Attempting to factorize n: 323...
Factors of n: 17, 19
Recovered private key (n, d): (323, 235)
Decoded Message: HELLO
```

## ⚠️ Notes

* This tool is for educational purposes; it is **not secure** for real-world cryptography.
* Works best with small prime numbers for demonstration. Large primes are impractical without optimizations.
* Factorization for large RSA keys is computationally infeasible in Python without specialized libraries.

## 📂 File Structure

```
rsa_cli.py        # Main Python file containing all code
```
