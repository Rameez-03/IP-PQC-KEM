import unittest
import os
from mlkem import ML_KEM
import secrets

class TestMLKEM_PKE(unittest.TestCase):

    def setUp(self):
        self.kem = ML_KEM(param="ML-KEM-512")
        self.seed = secrets.token_bytes(32)
        self.message = secrets.token_bytes(32)
        self.randomness = secrets.token_bytes(32)
        self.ek, self.dk = self.kem.k_pke_keygen(self.seed)

    def test_keygen_output_lengths(self):
        self.assertEqual(len(self.ek), 384 * self.kem.k + 32)
        self.assertEqual(len(self.dk), 384 * self.kem.k)

    def test_encrypt_decrypt_success(self):
        #print("Original Message:", self.message.hex())
        c = self.kem.k_pke_encrypt(self.ek, self.message, self.randomness)
        #print("Ciphertext:", c.hex())
        m_prime = self.kem.k_pke_decrypt(self.dk, c)
        #print("Decrypted Message:", m_prime.hex())
        self.assertEqual(m_prime, self.message)

    def test_decrypt_fails_on_modified_ciphertext(self):
        c = self.kem.k_pke_encrypt(self.ek, self.message, self.randomness)
        c = bytearray(c)
        c[0] ^= 0xFF  # Flip a bit
        m_prime = self.kem.k_pke_decrypt(self.dk, bytes(c))
        self.assertNotEqual(m_prime, self.message)

    def test_encrypt_decrypt_different_keys(self):
        ek2, dk2 = self.kem.k_pke_keygen(secrets.token_bytes(32))
        c = self.kem.k_pke_encrypt(self.ek, self.message, self.randomness)
        m_prime = self.kem.k_pke_decrypt(dk2, c)
        self.assertNotEqual(m_prime, self.message)

    def test_multiple_encryptions_different_ciphertexts(self):
        c1 = self.kem.k_pke_encrypt(self.ek, self.message, secrets.token_bytes(32))
        c2 = self.kem.k_pke_encrypt(self.ek, self.message, secrets.token_bytes(32))
        self.assertNotEqual(c1, c2)

    def test_encrypts_to_expected_length(self):
        c = self.kem.k_pke_encrypt(self.ek, self.message, self.randomness)
        expected_len = (32 * self.kem.du * self.kem.k) + (32 * self.kem.dv)
        self.assertEqual(len(c), expected_len)

    def test_invalid_decryption_data(self):
        bad_ciphertext = secrets.token_bytes(100)
        with self.assertRaises(Exception):
            self.kem.k_pke_decrypt(self.dk, bad_ciphertext)

    def test_encrypt_decrypt_with_all_zero_message(self):
        zero_message = bytes([0] * 32)
        c = self.kem.k_pke_encrypt(self.ek, zero_message, self.randomness)
        m_prime = self.kem.k_pke_decrypt(self.dk, c)
        self.assertEqual(m_prime, zero_message)

    def test_encrypt_decrypt_with_all_ff_message(self):
        ff_message = bytes([0xFF] * 32)
        c = self.kem.k_pke_encrypt(self.ek, ff_message, self.randomness)
        m_prime = self.kem.k_pke_decrypt(self.dk, c)
        self.assertEqual(m_prime, ff_message)

    def test_decrypt_with_invalid_key_type(self):
        c = self.kem.k_pke_encrypt(self.ek, self.message, self.randomness)
        with self.assertRaises(Exception):
            self.kem.k_pke_decrypt("not_bytes", c)

    def test_encrypt_with_non_bytes_input(self):
        with self.assertRaises(Exception):
            self.kem.k_pke_encrypt(self.ek, 12345, self.randomness)

if __name__ == "__main__":
    unittest.main()
