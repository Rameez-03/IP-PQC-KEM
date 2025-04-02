# Individual Project - Post-Quantum Cryptography: ML-KEM Implementation

This project implements the **Module Lattice-based Key Encapsulation Mechanism (ML-KEM)**, as specified in **NIST FIPS 203**. It includes both Public Key Encryption (PKE) and Key Encapsulation Mechanism (KEM) components along with full polynomial arithmetic using Number Theoretic Transform (NTT), and tests for validation.

---

## 📂 Project Structure

```
IP-PQC-KEM/
├── polynomials.py     # Core algorithms: NTT, sampling, encoding/decoding
├── mlkem.py           # ML-KEM logic: keygen, encryption, decryption
├── test_mlkem.py      # Unit tests for the ML-KEM implementation
├── test_pke.py        # Unit tests for the PKE layer (keygen, encrypt, decrypt)
├── requirements.txt   # Python package dependencies
└── README.md          # Project documentation
```

---

## ✅ Setup Instructions

### 1. Clone or Download

```bash
git clone <your-repo-url>
cd IP-PQC-KEM
```

### 2. Install Dependencies

Use pip to install required libraries:

```bash
pip install -r requirements.txt
```

This project uses:
- `pycryptodome`: for cryptographic primitives (SHAKE, SHA3)
- `unittest`: built-in Python test framework

---

## ▶️ Running the Code

### Run ML-KEM Simulation and Test Vectors

```bash
python mlkem.py
```

This script loads internal test vectors and validates the implementation of:
- Key Generation
- Encapsulation
- Decapsulation

Output is printed for expected and obtained values of the shared key.

---

## 🧪 Run Unit Tests

### Run PKE Tests (Public Key Encryption)

```bash
python test_pke.py
```

Covers:
- Key generation length
- Encryption/decryption correctness
- Invalid inputs, tampering, randomness
- Error handling for corrupted data

### Run ML-KEM Tests (Encapsulation/Decapsulation)

```bash
python test_mlkem.py
```

Covers:
- Internal KEM API: `keygen_internal`, `encaps_internal`, `decaps_internal`
- Known-answer test (KAT) cases from FIPS203

---

## 🔐 Cryptographic Notes

- All polynomials are 256-coefficient integers mod `q = 3329`
- Secure randomness derived from SHAKE256
- Compression & decompression reduce communication overhead
- NTT-based multiplication optimizes polynomial arithmetic

---

## 📚 References

- [NIST FIPS 203 Final](https://csrc.nist.gov/publications/detail/fips/203/final)
- Official ML-KEM Parameter Sets: ML-KEM-512, ML-KEM-768, ML-KEM-1024

---

## 🛡️ Disclaimer

This code is provided **for educational and research purposes** only.
It is **not production hardened or side-channel resistant**.

---

© 2025 Rameez. All rights reserved.

