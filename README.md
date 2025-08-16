# CryptoDemo

A simple .NET console application demonstrating three cryptographic techniques:
- AES (symmetric encryption)
- RSA (asymmetric encryption)
- Hybrid (AES + RSA)

## How to Run

1. **Requirements:**
   - .NET 9.0 SDK or later
   - Windows, macOS, or Linux

2. **Build and Run:**
   - Open a terminal in the project directory.
   - Run:
     ```powershell
     dotnet run
     ```

3. **Usage:**
   - Follow the on-screen menu:
     - Enter `1` for AES demo
     - Enter `2` for RSA demo
     - Enter `3` for Hybrid demo
     - Enter `4` or press Enter to exit
   - Enter the plaintext you want to encrypt when prompted.

## Crypto Functions

### 1. AES (Symmetric Encryption)
- **Function:** `DemoAes`
- **Description:**
  - Generates a random 256-bit AES key and IV.
  - Encrypts the input plaintext using AES in CBC mode with PKCS7 padding.
  - Decrypts the ciphertext to verify correctness.
  - Displays the key, IV, ciphertext (all Base64-encoded), and decrypted text.

### 2. RSA (Asymmetric Encryption)
- **Function:** `DemoRsa`
- **Description:**
  - Generates a new 2048-bit RSA key pair.
  - Exports the public and private keys in standard formats.
  - Encrypts the plaintext using the public key and OAEP-SHA256 padding.
  - Decrypts the ciphertext using the private key.
  - Displays the public/private keys, ciphertext (all Base64-encoded), and decrypted text.

### 3. Hybrid (AES + RSA)
- **Function:** `DemoHybrid`
- **Description:**
  - Generates a random AES key and IV.
  - Encrypts the plaintext with AES (as above).
  - Generates a new RSA key pair.
  - Packages the AES key and IV together, then encrypts ("wraps") them with the RSA public key.
  - Demonstrates decryption by unwrapping the AES key/IV with the RSA private key and decrypting the ciphertext.
  - Displays the AES key, IV, ciphertext, wrapped key (all Base64-encoded), and decrypted text.

## Output Styling
- Labels and values are color-coded and aligned for clarity.
- All cryptographic outputs are shown in Base64 for easy copying and inspection.

---

**Author:** Robert Jansz , https://github.com/QuBaR/
