import binascii
import ctypes

# Load the shared library (DLL) containing the C functions
crypto_vrf = ctypes.CDLL("C:/Users/SISSY/PycharmProjects/pythonProject/libsodium.dll")

# Function prototypes
crypto_vrf.crypto_vrf_publickeybytes.restype = ctypes.c_size_t
crypto_vrf.crypto_vrf_secretkeybytes.restype = ctypes.c_size_t
crypto_vrf.crypto_vrf_seedbytes.restype = ctypes.c_size_t
crypto_vrf.crypto_vrf_proofbytes.restype = ctypes.c_size_t
crypto_vrf.crypto_vrf_outputbytes.restype = ctypes.c_size_t
crypto_vrf.crypto_vrf_primitive.restype = ctypes.c_char_p

crypto_vrf.crypto_vrf_keypair.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
crypto_vrf.crypto_vrf_keypair_from_seed.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte),
                                                    ctypes.POINTER(ctypes.c_ubyte)]
crypto_vrf.crypto_vrf_is_valid_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
crypto_vrf.crypto_vrf_prove.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte),
                                        ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong]
crypto_vrf.crypto_vrf_verify.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte),
                                         ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte),
                                         ctypes.c_ulonglong]
crypto_vrf.crypto_vrf_proof_to_hash.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
crypto_vrf.crypto_vrf_sk_to_pk.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
crypto_vrf.crypto_vrf_sk_to_seed.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]


# Define the c_ubyte_Array type
class c_ubyte_Array(ctypes.Structure):
    _fields_ = [("data", ctypes.c_ubyte * 1)]


# Wrapper functions
def crypto_vrf_publickeybytes():
    return crypto_vrf.crypto_vrf_publickeybytes()


def crypto_vrf_secretkeybytes():
    return crypto_vrf.crypto_vrf_secretkeybytes()


def crypto_vrf_seedbytes():
    return crypto_vrf.crypto_vrf_seedbytes()


def crypto_vrf_proofbytes():
    return crypto_vrf.crypto_vrf_proofbytes()


def crypto_vrf_outputbytes():
    return crypto_vrf.crypto_vrf_outputbytes()


def crypto_vrf_primitive():
    return crypto_vrf.crypto_vrf_primitive().decode("utf-8")


def crypto_vrf_keypair():
    pk = (ctypes.c_ubyte * crypto_vrf_publickeybytes())()
    sk = (ctypes.c_ubyte * crypto_vrf_secretkeybytes())()
    crypto_vrf.crypto_vrf_keypair(pk, sk)
    return pk, sk


def crypto_vrf_keypair_from_seed(seed):
    pk = (ctypes.c_ubyte * crypto_vrf_publickeybytes())()
    sk = (ctypes.c_ubyte * crypto_vrf_secretkeybytes())()
    seed_ptr = ctypes.cast(seed, ctypes.POINTER(ctypes.c_ubyte))
    crypto_vrf.crypto_vrf_keypair_from_seed(pk, sk, seed_ptr)
    return pk, sk


def crypto_vrf_is_valid_key(pk):
    pk_ptr = ctypes.cast(pk, ctypes.POINTER(ctypes.c_ubyte))
    return crypto_vrf.crypto_vrf_is_valid_key(pk_ptr)


def crypto_vrf_prove(skpk, m):
    proof = (ctypes.c_ubyte * crypto_vrf_proofbytes())()
    skpk_ptr = ctypes.cast(skpk, ctypes.POINTER(ctypes.c_ubyte))
    m_ptr = ctypes.cast(m, ctypes.POINTER(ctypes.c_ubyte))
    crypto_vrf.crypto_vrf_prove(proof, skpk_ptr, m_ptr, len(m))
    return proof


def crypto_vrf_verify(pk, proof, m):
    output = (ctypes.c_ubyte * crypto_vrf_outputbytes())()
    pk_ptr = ctypes.cast(pk, ctypes.POINTER(ctypes.c_ubyte))
    proof_ptr = ctypes.cast(proof, ctypes.POINTER(ctypes.c_ubyte))
    m_ptr = ctypes.cast(m, ctypes.POINTER(ctypes.c_ubyte))
    crypto_vrf.crypto_vrf_verify(output, pk_ptr, proof_ptr, m_ptr, len(m))
    return output


def crypto_vrf_proof_to_hash(proof):
    hash_ = (ctypes.c_ubyte * crypto_vrf_outputbytes())()
    proof_ptr = ctypes.cast(proof, ctypes.POINTER(ctypes.c_ubyte))
    crypto_vrf.crypto_vrf_proof_to_hash(hash_, proof_ptr)
    return hash_


def crypto_vrf_sk_to_pk(skpk):
    pk = (ctypes.c_ubyte * crypto_vrf_publickeybytes())()
    skpk_ptr = ctypes.cast(skpk, ctypes.POINTER(ctypes.c_ubyte))
    crypto_vrf.crypto_vrf_sk_to_pk(pk, skpk_ptr)
    return pk


def crypto_vrf_sk_to_seed(skpk):
    seed = (ctypes.c_ubyte * crypto_vrf_seedbytes())()
    skpk_ptr = ctypes.cast(skpk, ctypes.POINTER(ctypes.c_ubyte))
    crypto_vrf.crypto_vrf_sk_to_seed(seed, skpk_ptr)
    return seed


def convert_from_hex(hex, length):
    byte_sequence = bytes.fromhex(hex)

    # Create an instance of c_ubyte_Array
    c_ubyte_array = (c_ubyte_Array * length)()

    # Copy the bytes into the c_ubyte_Array_80 object
    for i in range(length):
        c_ubyte_array[i].data[0] = byte_sequence[i]

    return c_ubyte_array


# Example usage
if __name__ == "__main__":
    pk, sk = crypto_vrf_keypair()
    print("Public Key:", binascii.hexlify(pk).decode('utf-8'))
    print("Secret Key:", binascii.hexlify(sk).decode('utf-8'))

    message = b"Hello, VRF!"
    proof = crypto_vrf_prove(sk, message)
    print("Proof:", binascii.hexlify(proof).decode('utf-8'))

    output = crypto_vrf_verify(pk, proof, message)
    print("Output:", binascii.hexlify(output).decode('utf-8'))

    # hash from proof is the same as the output
    hash_from_proof = crypto_vrf_proof_to_hash(proof)
    print("Hash from Proof:", binascii.hexlify(hash_from_proof).decode('utf-8'))

    pk_from_sk = crypto_vrf_sk_to_pk(sk)
    print("Public Key from Secret Key:", binascii.hexlify(pk_from_sk).decode('utf-8'))

    seed = crypto_vrf_sk_to_seed(sk)
    print("Seed from Secret Key:", binascii.hexlify(seed).decode('utf-8'))

    if binascii.hexlify(hash_from_proof).decode('utf-8') == binascii.hexlify(output).decode('utf-8'):
        print("VRF Proof is valid.")
    else:
        print("VRF Proof is NOT valid.")
