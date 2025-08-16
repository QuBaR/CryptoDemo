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
     - `1` AES (symmetrisk, CBC)
     - `2` AES-GCM (symmetrisk, GCM)
     - `3` Jämför AES CBC och GCM
     - `4` RSA (asymmetrisk)
     - `5` Hybrid (AES + RSA)
     - `6` Filkryptering (AES-GCM)
     - `7` Avsluta
   - För menyval 1–5: Ange klartext när du blir ombedd.
   - För menyval 6: Ange filväg, välj om du vill kryptera (K) eller dekryptera (D), och ange lösenord.

## Crypto Functions

### 1. AES (Symmetric, CBC)
- **Function:** `DemoAes`
- **Description:**
  - Generates a random 256-bit AES key and IV.
  - Encrypts the input plaintext using AES in CBC mode with PKCS7 padding.
  - Decrypts the ciphertext to verify correctness.
  - Displays the key, IV, ciphertext (all Base64-encoded), and decrypted text.

### 2. AES-GCM (Symmetric, GCM)
- **Function:** `DemoAesGcm`
- **Description:**
  - Generates a random 256-bit AES key and 96-bit nonce.
  - Encrypts the input plaintext using AES in GCM mode (authenticated encryption).
  - Decrypts and verifies the ciphertext and tag.
  - Displays the key, nonce, ciphertext, tag (all Base64-encoded), and decrypted text.

### 3. Jämför AES CBC och GCM
- **Function:** `CompareAesCbcGcm`
- **Description:**
  - Kör både CBC och GCM med samma plaintext och nyckel.
  - Visar och jämför utdata för båda metoderna.

### 4. RSA (Asymmetric Encryption)
- **Function:** `DemoRsa`
- **Description:**
  - Generates a new 2048-bit RSA key pair.
  - Exports the public and private keys in standard formats.
  - Encrypts the plaintext using the public key and OAEP-SHA256 padding.
  - Decrypts the ciphertext using the private key.
  - Displays the public/private keys, ciphertext (all Base64-encoded), and decrypted text.

### 5. Hybrid (AES + RSA)
- **Function:** `DemoHybrid`
- **Description:**
  - Generates a random AES key and IV.
  - Encrypts the plaintext with AES (as above).
  - Generates a new RSA key pair.
  - Packages the AES key and IV together, then encrypts ("wraps") them with the RSA public key.
  - Demonstrates decryption by unwrapping the AES key/IV with the RSA private key and decrypting the ciphertext.
  - Displays the AES key, IV, ciphertext, wrapped key (all Base64-encoded), and decrypted text.

### 6. Filkryptering (AES-GCM)
- **Functions:** `FileEncryptionMenu`, `EncryptFileAesGcm`, `DecryptFileAesGcm`
- **Description:**
  - Kryptera eller dekryptera valfri fil med lösenord.
  - AES-nyckel härleds från lösenordet med PBKDF2 (100 000 iterationer, SHA-256).
  - Filformat: [salt][nonce][tag][ciphertext].
  - Ange filväg, välj K (kryptera) eller D (dekryptera), och ange lösenord.
  - Krypterad fil får ändelsen `.aesgcm`.

## Output Styling
- Labels and values are color-coded and aligned for clarity.
- All cryptographic outputs are shown in Base64 for easy copying and inspection.
- File encryption output is written to disk, not shown in terminal.

---

**Author:** Robert Jansz , https://github.com/QuBaR/
