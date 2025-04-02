from test_mlkem import test_mlkem

from Crypto.Hash import SHAKE128, SHAKE256, SHA3_256, SHA3_512

from polynomials import (
    ML_KEM_ZETA_NTT, ML_KEM_ZETA_MUL, byte_decode, byte_encode,
    sample_ntt, sample_poly_cbd, ntt, ntt_inverse,
    multiply_ntts, base_case_multiply, poly_add, poly_sub
)

# Table 2. Approved parameter sets for ML-KEM
ML_KEM_PARAM = {
    "ML-KEM-512": (2, 3, 2, 10, 4),
    "ML-KEM-768": (3, 2, 2, 10, 4),
    "ML-KEM-1024": (4, 2, 2, 11, 5)
}

class ML_KEM:
    """
    This class implements the ML-KEM (Module Lattice-based Key Encapsulation Mechanism) system,
    including Key Generation, Encryption, and Decryption as described in the NIST FIPS 203 standard.
    """

    def __init__(self, param='ML-KEM-1024'):
        """Initialize the ML-KEM instance using a specific parameter set."""
        if param not in ML_KEM_PARAM:
            raise ValueError
        self.q = 3329                 # Modulus used for all arithmetic
        self.n = 256                 # Polynomial degree
        (self.k, self.eta1, self.eta2, self.du, self.dv) = ML_KEM_PARAM[param]  # Load parameters

    # === 4.1 Cryptographic Hash Functions ===

    def h(self, x):
        """Hash function H using SHA3-256."""
        return SHA3_256.new(x).digest()

    def g(self, x):
        """Hash function G using SHA3-512, output split into two halves."""
        h = SHA3_512.new(x).digest()
        return (h[0:32], h[32:64])

    def j(self, s):
        """Hash function J using SHAKE256 to produce 32 bytes of output."""
        return SHAKE256.new(s).read(32)

    def prf(self, eta, s, b):
        """Pseudo-random function used to sample noise polynomials."""
        return SHAKE256.new(s + bytes([b])).read(64 * eta)

    # === 4.2.1 Conversion and Compression Algorithms ===

    def compress(self, d, xv):
        """Compress a polynomial by reducing its precision to d bits."""
        return [((x << d) + (self.q - 1) // 2) // self.q % (1 << d) for x in xv]

    def decompress(self, d, yv):
        """Decompress a polynomial from d-bit representation back to full precision."""
        return [(self.q * y + (1 << (d - 1))) >> d for y in yv]

    # === Helper Functions ===

    def sample_poly_vector(self, length, eta, seed, counter_start):
        """Generate a list of polynomials sampled using CBD from SHAKE-based PRF."""
        vec = []
        for i in range(length):
            prf_output = self.prf(eta, seed, counter_start + i)  # Generate pseudorandom bytes
            vec.append(sample_poly_cbd(eta, prf_output, self.q))  # Convert bytes to polynomial
        return vec

    def generate_matrix_from_seed(self, rho, transpose=False):
        """
        Generate a matrix A (or its transpose A^T) deterministically from a seed `rho`.
        Each element A[i][j] is a polynomial sampled with NTT-compatible structure.
        """
        A_data = [[sample_ntt(rho + bytes([j, i]), self.q) for j in range(self.k)] for i in range(self.k)]
        if transpose:
            A_data = [list(row) for row in zip(*A_data)]  # Transpose the matrix
        return A_data

    def poly_mat_vec_mul_or_dot(self, A, B, dot=False):
        """
        Perform matrix-vector multiplication or dot product over polynomials.

        Parameters:
            A (list): Matrix of polynomials (k x k or 1 x k)
            B (list): Vector of polynomials (k)
            dot (bool): Whether to perform dot product (default: False)
        """
        if dot:
            result = [0] * 256
            for i in range(self.k):
                product = multiply_ntts(A[i], B[i], self.q)
                result = poly_add(result, product, self.q)
            return result
        else:
            result = [[0] * 256 for _ in range(self.k)]
            for i in range(self.k):
                for j in range(self.k):
                    product = multiply_ntts(A[i][j], B[j], self.q)
                    result[i] = poly_add(result[i], product, self.q)
            return result

    #   Algorithm 13, K-PKE.KeyGen(d)
    def k_pke_keygen(self, d):
        """
        Key generation algorithm for ML-KEM Public Key Encryption (PKE).

        It generates a random matrix A from a seed, and secret vectors s and e.
        Outputs public and private keys as encoded byte strings.
        """
        (rho, sig) = self.g(d + bytes([self.k]))

        a = self.generate_matrix_from_seed(rho)  # Generate matrix A deterministically

        s = self.sample_poly_vector(self.k, self.eta1, sig, 0)        # Sample secret vector s
        e = self.sample_poly_vector(self.k, self.eta1, sig, self.k)   # Sample error vector e

        s = [ntt(v, self.q) for v in s]  # Transform s to NTT domain
        e = [ntt(v, self.q) for v in e]  # Transform e to NTT domain

        t = self.poly_mat_vec_mul_or_dot(a, s)  # t = A * s
        t = [poly_add(t[i], e[i], self.q) for i in range(self.k)]  # t = A * s + e

        ek_pke = byte_encode(12, t, self.q) + rho  # Public key encoding
        dk_pke = byte_encode(12, s, self.q)        # Secret key encoding
        return (ek_pke, dk_pke)

    #   Algorithm 14, K-PKE.Encrypt(ek_PKE, m, r)
    def k_pke_encrypt(self, ek_pke, m, r):
        """
        PKE encryption algorithm: encrypts message `m` under public key `ek_pke`
        using randomness `r`. Outputs ciphertext.
        """
        n = 0
        t = [byte_decode(12, ek_pke[384*i:384*(i+1)], self.q) for i in range(self.k)]  # Extract t
        rho = ek_pke[384*self.k : 384*self.k + 32]  # Extract rho

        a = self.generate_matrix_from_seed(rho, transpose=True)  # Generate A^T

        y = self.sample_poly_vector(self.k, self.eta1, r, n); n += self.k  # Ephemeral secret y
        e1 = self.sample_poly_vector(self.k, self.eta2, r, n); n += self.k # Error vector e1
        e2 = sample_poly_cbd(self.eta2, self.prf(self.eta2, r, n), self.q) # Error poly e2

        y = [ntt(v, self.q) for v in y]  # Transform y to NTT domain

        u = self.poly_mat_vec_mul_or_dot(a, y)  # u = A^T * y
        for i in range(self.k):
            u[i] = ntt_inverse(u[i], self.q)
            u[i] = poly_add(u[i], e1[i], self.q)  # Add error e1

        mu = self.decompress(1, byte_decode(1, m, self.q))  # Decompress the encoded message

        v = self.poly_mat_vec_mul_or_dot(t, y, dot=True)  # v = t^T * y
        v = ntt_inverse(v, self.q)
        v = poly_add(v, e2, self.q)  # Add error e2
        v = poly_add(v, mu, self.q) # Add message

        # Encode ciphertext as two components: c1 (from u) and c2 (from v)
        c1 = b''.join(byte_encode(self.du, self.compress(self.du, u[i]), self.q) for i in range(self.k))
        c2 = byte_encode(self.dv, self.compress(self.dv, v), self.q)
        return c1 + c2

    #   Algorithm 15, K-PKE.Decrypt(dk_PKE, c)
    def k_pke_decrypt(self, dk_pke, c):
        """Decrypt ciphertext `c` using secret key `dk_pke` and return the recovered message."""
        c1 = c[0 : 32*self.du*self.k]   # Extract u
        c2 = c[32*self.du*self.k : 32*(self.du*self.k + self.dv)]  # Extract v

        up = [self.decompress(self.du, byte_decode(self.du, c1[32*self.du*i : 32*self.du*(i+1)], self.q)) for i in range(self.k)]
        vp = self.decompress(self.dv, byte_decode(self.dv, c2, self.q))

        s = [byte_decode(12, dk_pke[384*i:384*(i+1)], self.q) for i in range(self.k)]

        w = [0] * 256
        for i in range(self.k):
            w = poly_add(w, multiply_ntts(s[i], ntt(up[i], self.q), self.q), self.q)

        w = poly_sub(vp, ntt_inverse(w, self.q), self.q)
        m = byte_encode(1, self.compress(1, w), self.q)
        return m

    #   Algorithm 16, ML-KEM.KeyGen_internal(d, z)
    def keygen_internal(self, d, z, param=None):
        """ML-KEM key generation: returns encapsulated public and secret keys."""
        if param != None:
            self.__init__(param)
        (ek_pke, dk_pke) = self.k_pke_keygen(d)
        ek = ek_pke
        dk = dk_pke + ek + self.h(ek) + z  # Construct the secret key with public key hash and z
        return (ek, dk)

    #   Algorithm 17, ML-KEM.Encaps_internal(ek, m)
    def encaps_internal(self, ek, m, param=None):
        """Encapsulate shared key `m` using public key `ek`. Returns (shared key, ciphertext)."""
        if param != None:
            self.__init__(param)
        (k, r) = self.g(m + self.h(ek))  # Derive shared key and randomness
        c = self.k_pke_encrypt(ek, m, r)
        return (k, c)

    #   Algorithm 18, ML-KEM.Decaps_internal(dk, c)
    def decaps_internal(self, dk, c, param=None):
        """Decapsulate ciphertext `c` using secret key `dk`. Returns shared key."""
        if param != None:
            self.__init__(param)

        # Extract keys and values from concatenated dk
        dk_pke = dk[0 : 384*self.k]
        ek_pke = dk[384*self.k : 768*self.k + 32]
        h = dk[768*self.k + 32 : 768*self.k + 64]
        z = dk[768*self.k + 64 : 768*self.k + 96]

        mp = self.k_pke_decrypt(dk_pke, c)
        (kp, rp) = self.g(mp + h)       # Recompute shared key and randomness
        kk = self.j(z + c)              # Fallback key
        cp = self.k_pke_encrypt(ek_pke, mp, rp)
        if c != cp:
            kp = kk                     # If ciphertext doesn't match, use fallback key
        return kp

    #   Algorithm 19
    def keygen(self):
        d = self.random_bytes(32)
        z = self.random_bytes(32)
        (
            ek,
            dk,
        ) = self._keygen_internal(d, z)
        return (ek, dk)

    #   Algorithm 20
    def encaps(self, ek):
        # Create random tokens
        m = self.random_bytes(32)
        K, c = self._encaps_internal(ek, m)
        return K, c

    #   Algorithm 21
    def decaps(self, dk, c):
        try:
            K_prime = self._decaps_internal(dk, c)
        except ValueError as e:
            raise ValueError(
                f"Validation of decapsulation key or ciphertext failed: {e = }"
            )
        return K_prime

# Entry point for running unit tests
if __name__ == '__main__':
    ml_kem = ML_KEM()
    test_mlkem(
        ml_kem.keygen_internal,
        ml_kem.encaps_internal,
        ml_kem.decaps_internal,
        '(fips203.py)'
    )
