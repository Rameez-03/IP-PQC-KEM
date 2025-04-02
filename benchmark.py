import timeit
import secrets
from mlkem import ML_KEM
from memory_profiler import memory_usage


def measure_memory(func, *args):
    """
    Helper to measure max memory used by a function call.
    Returns result and peak memory usage.
    """
    mem_usage, result = memory_usage((func, args), retval=True, max_usage=True)
    return result, mem_usage

def benchmark_pke(kem, runs=100):
    print("\n[Benchmarking PKE Functions]")
    d = secrets.token_bytes(32)
    m = secrets.token_bytes(32)
    r = secrets.token_bytes(32)

    ek, dk = kem.k_pke_keygen(d)

    keygen_time = timeit.timeit(lambda: kem.k_pke_keygen(d), number=runs)
    print(f"Average KeyGen time (PKE): {keygen_time / runs:.6f} s")

    encrypt_time = timeit.timeit(lambda: kem.k_pke_encrypt(ek, m, r), number=runs)
    print(f"Average Encrypt time (PKE): {encrypt_time / runs:.6f} s")

    c = kem.k_pke_encrypt(ek, m, r)
    decrypt_time = timeit.timeit(lambda: kem.k_pke_decrypt(dk, c), number=runs)
    print(f"Average Decrypt time (PKE): {decrypt_time / runs:.6f} s")

    # Memory usage
    _, mem_keygen = measure_memory(kem.k_pke_keygen, d)
    print(f"Max memory KeyGen (PKE): {mem_keygen:.2f} MB")

    _, mem_encrypt = measure_memory(kem.k_pke_encrypt, ek, m, r)
    print(f"Max memory Encrypt (PKE): {mem_encrypt:.2f} MB")

    _, mem_decrypt = measure_memory(kem.k_pke_decrypt, dk, c)
    print(f"Max memory Decrypt (PKE): {mem_decrypt:.2f} MB")

def benchmark_kem(kem, runs=100):
    print("\n[Benchmarking ML-KEM Functions]")
    d = secrets.token_bytes(32)
    z = secrets.token_bytes(32)
    m = secrets.token_bytes(32)

    keygen_time = timeit.timeit(lambda: kem.keygen_internal(d, z), number=runs)
    print(f"Average KeyGen time (KEM): {keygen_time / runs:.6f} s")

    ek, dk = kem.keygen_internal(d, z)
    encaps_time = timeit.timeit(lambda: kem.encaps_internal(ek, m), number=runs)
    print(f"Average Encaps time (KEM): {encaps_time / runs:.6f} s")

    _, c = kem.encaps_internal(ek, m)
    decaps_time = timeit.timeit(lambda: kem.decaps_internal(dk, c), number=runs)
    print(f"Average Decaps time (KEM): {decaps_time / runs:.6f} s")

    # Memory usage
    _, mem_keygen = measure_memory(kem.keygen_internal, d, z)
    print(f"Max memory KeyGen (KEM): {mem_keygen:.2f} MB")

    _, mem_encaps = measure_memory(kem.encaps_internal, ek, m)
    print(f"Max memory Encaps (KEM): {mem_encaps:.2f} MB")

    _, mem_decaps = measure_memory(kem.decaps_internal, dk, c)
    print(f"Max memory Decaps (KEM): {mem_decaps:.2f} MB")

def run_all_benchmarks(param='ML-KEM-512', runs=100):
    print(f"Running benchmarks for parameter set: {param} ({runs} runs)")
    kem = ML_KEM(param)

    benchmark_pke(kem, runs)
    benchmark_kem(kem, runs)

if __name__ == "__main__":
    run_all_benchmarks(param='ML-KEM-512', runs=100)