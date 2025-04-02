from Crypto.Hash import SHAKE128, SHAKE256, SHA3_256, SHA3_512

#   The following 128 numbers are the values of zeta^BitRev7(i) mod q
#   for i in {0, ... , 127}. These numbers are used in Algs. 9 and 10.
ML_KEM_ZETA_NTT = [
    1,      1729,   2580,   3289,   2642,   630,    1897,   848,
    1062,   1919,   193,    797,    2786,   3260,   569,    1746,
    296,    2447,   1339,   1476,   3046,   56,     2240,   1333,
    1426,   2094,   535,    2882,   2393,   2879,   1974,   821,
    289,    331,    3253,   1756,   1197,   2304,   2277,   2055,
    650,    1977,   2513,   632,    2865,   33,     1320,   1915,
    2319,   1435,   807,    452,    1438,   2868,   1534,   2402,
    2647,   2617,   1481,   648,    2474,   3110,   1227,   910,
    17,     2761,   583,    2649,   1637,   723,    2288,   1100,
    1409,   2662,   3281,   233,    756,    2156,   3015,   3050,
    1703,   1651,   2789,   1789,   1847,   952,    1461,   2687,
    939,    2308,   2437,   2388,   733,    2337,   268,    641,
    1584,   2298,   2037,   3220,   375,    2549,   2090,   1645,
    1063,   319,    2773,   757,    2099,   561,    2466,   2594,
    2804,   1092,   403,    1026,   1143,   2150,   2775,   886,
    1722,   1212,   1874,   1029,   2110,   2935,   885,    2154 ]

#   When implementing Algorithm 11, the values zeta^{2*BitRev7(i)+1} mod q
#   need to be computed. The following array contains these values for
#   i in {0, ... , 127}:
ML_KEM_ZETA_MUL = [
    17,     -17,    2761,   -2761,  583,    -583,   2649,   -2649,
    1637,   -1637,  723,    -723,   2288,   -2288,  1100,   -1100,
    1409,   -1409,  2662,   -2662,  3281,   -3281,  233,    -233,
    756,    -756,   2156,   -2156,  3015,   -3015,  3050,   -3050,
    1703,   -1703,  1651,   -1651,  2789,   -2789,  1789,   -1789,
    1847,   -1847,  952,    -952,   1461,   -1461,  2687,   -2687,
    939,    -939,   2308,   -2308,  2437,   -2437,  2388,   -2388,
    733,    -733,   2337,   -2337,  268,    -268,   641,    -641,
    1584,   -1584,  2298,   -2298,  2037,   -2037,  3220,   -3220,
    375,    -375,   2549,   -2549,  2090,   -2090,  1645,   -1645,
    1063,   -1063,  319,    -319,   2773,   -2773,  757,    -757,
    2099,   -2099,  561,    -561,   2466,   -2466,  2594,   -2594,
    2804,   -2804,  1092,   -1092,  403,    -403,   1026,   -1026,
    1143,   -1143,  2150,   -2150,  2775,   -2775,  886,    -886,
    1722,   -1722,  1212,   -1212,  1874,   -1874,  1029,   -1029,
    2110,   -2110,  2935,   -2935,  885,    -885,   2154,   -2154 ]

#   Algorithm 3, BitsToBytes(b)
def bits_to_bytes(b):
    a = bytearray(len(b) // 8)  # Allocate byte array for result
    for i in range(0, len(b), 8):  # Process every 8 bits
        x = 0
        for j in range(8):  # Combine bits into a byte
            x += b[i + j] << j
        a[i // 8] = x  # Store byte in output array
    return a

#   Algorithm 4, BytesToBits(B)
def bytes_to_bits(b):
    a = bytearray(8 * len(b))  # Allocate 8 bits per byte
    for i in range(0, 8 * len(b), 8):
        x = b[i // 8]  # Get the current byte
        for j in range(8):
            a[i + j] = (x >> j) & 1  # Extract the j-th bit
    return a

#   Algorithm 5, ByteEncode_d(F)
def byte_encode(d, f, q):
    if isinstance(f[0], list):  # Handle list of polynomials
        return b''.join(byte_encode(d, x, q) for x in f)

    m = (1 << d) if d < 12 else q  # Use 2^d or q depending on d
    b = bytearray(256 * d)  # Allocate bit array
    for i in range(256):
        a = f[i] % m  # Get value modulo m
        for j in range(d):
            b[i * d + j] = a % 2  # Extract bits
            a //= 2
    return bits_to_bytes(b)  # Convert bit array to bytes

#   Algorithm 6, ByteDecode_d(B)
def byte_decode(d, b, q):
    m = (1 << d) if d < 12 else q  # Use 2^d or q as modulus
    b = bytes_to_bits(b)  # Convert to bit array
    f = []
    for i in range(256):
        x = 0
        for j in range(d):
            x += b[i * d + j] << j  # Reconstruct integer from bits
        f.append(x % m)
    return f

#   Algorithm 7, SampleNTT(B)
def sample_ntt(b, q):
    xof = SHAKE128.new(b)  # Create SHAKE128 instance with seed b
    j = 0
    a = []
    while j < 256:
        c = xof.read(3)  # Read 3 bytes = 24 bits
        d1 = c[0] + 256 * (c[1] % 16)  # First 12-bit candidate
        d2 = (c[1] // 16) + 16 * c[2]  # Second 12-bit candidate
        if d1 < q:
            a.append(d1)
            j += 1
        if d2 < q and j < 256:
            a.append(d2)
            j += 1
    return a

#   Algorithm 8, SamplePolyCBD_eta(B)
def sample_poly_cbd(eta, b, q):
    b = bytes_to_bits(b)  # Convert input bytes to bits
    f = [0] * 256
    for i in range(256):
        x = sum(b[2 * i * eta : (2 * i + 1) * eta])  # Count 1s in first half
        y = sum(b[(2 * i + 1) * eta : (2 * i + 2) * eta])  # Count 1s in second half
        f[i] = (x - y) % q  # Compute centered binomial sample
    return f

#   Algorithm 9, NTT(f)
def ntt(f, q):
    f = f.copy()
    i = 1  # Index into zeta array
    le = 128  # Initial layer size
    while le >= 2:
        for st in range(0, 256, 2 * le):  # Process blocks of 2*le size
            ze = ML_KEM_ZETA_NTT[i]  # Get twiddle factor
            i += 1
            for j in range(st, st + le):
                t = (ze * f[j + le]) % q  # Multiply by zeta and mod q
                f[j + le] = (f[j] - t) % q  # Butterfly operation
                f[j] = (f[j] + t) % q
        le //= 2  # Go to next layer
    return f

#   Algorithm 10, NTT^{−1}(~f)
def ntt_inverse(f, q):
    f = f.copy()
    i = 127  # Start from end of zeta table
    le = 2  # Initial layer size
    while le <= 128:
        for st in range(0, 256, 2 * le):
            ze = ML_KEM_ZETA_NTT[i]  # Twiddle factor
            i -= 1
            for j in range(st, st + le):
                t = f[j]  # Copy input
                f[j] = (t + f[j + le]) % q  # Butterfly merge
                f[j + le] = (ze * (f[j + le] - t)) % q  # Multiply difference
        le *= 2  # Double the size of the block
    return [(x * 3303) % q for x in f]  # Multiply by n^{-1} mod q

#   Algorithm 11, MultiplyNTTs(~f, ~g)
def multiply_ntts(f, g, q):
    h = []
    for i in range(0, 256, 2):
        h += base_case_multiply(f[i], f[i+1], g[i], g[i+1], ML_KEM_ZETA_MUL[i // 2], q)
    return h

#   Algorithm 12, BaseCaseMultiply(a0, a1, b0, b1, gamma)
def base_case_multiply(a0, a1, b0, b1, gam, q):
    c0 = (a0 * b0 + a1 * b1 * gam) % q  # Compute low part
    c1 = (a0 * b1 + a1 * b0) % q        # Compute high part
    return [c0, c1]

#   Helper functions

# Add two polynomials element-wise
def poly_add(f, g, q):
    return [ (f[i] + g[i]) % q for i in range(256) ]

# Subtract polynomial g from f element-wise
def poly_sub(f, g, q):
    return [ (f[i] - g[i]) % q for i in range(256) ]


