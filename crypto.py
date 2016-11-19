from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.kdf import pbkdf2

import ChatApp.exceptions as exceptions


# Generates Hash of Password on Client Side
def generate_client_hash_password(username, password):
    h = hashes.Hash(hashes.SHA512(), backend=default_backend())
    h.update(username)
    salt = h.finalize()
    kdf = pbkdf2.PBKDF2HMAC(hashes.SHA512(), length=64, salt=salt,
                            iterations=200000, backend=default_backend())
    pass_hash = kdf.derive(password)
    return pass_hash


# Verify Client Hash Password is correct
def verify_hash_password(client_hash, server_hash, salt):
    hopeful_hash = __salt_and_hash(client_hash, salt)
    return bytes_eq(hopeful_hash, server_hash)


# Generates Password Hash to be stored on Server
def generate_server_hash_password(username, password, salt):
    client_hash = generate_client_hash_password(username, password)
    return __salt_and_hash(client_hash, salt)


# Generated DH Pair using Elliptic Curve Cryptography
# Better check correct security parameter
def generate_dh_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub = private_key.public_key()
    return pub, private_key


def generate_rsa_pair():
    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048,
                                           backend=default_backend())
    return private_key.public_key(), private_key


def load_rsa_pair(priv_der, pub_der):
    private_key = serialization.load_der_private_key(priv_der.read(),
                                                     None,
                                                     default_backend())
    public_key = serialization.load_der_public_key(pub_der.read(),
                                                   default_backend())
    return public_key, private_key


# Should be used to get symmetric key like K(AS) or K(AB)
def derive_symmetric_key(private_key, public_key, n1, n2):
    shared_key = __get_shared_secret(private_key, public_key)
    salt = __xor(n1, n2)
    kdf = pbkdf2.PBKDF2HMAC(hashes.SHA512(), length=32, salt=salt,
                            iterations=5000, backend=default_backend())
    return kdf.derive(shared_key)


# Solve Client Puzzle
def solve_puzzle(ns, nc, d):
    x = 0
    while True:
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(ns)
        h.update(nc)
        h.update(bytes(x))
        if __is_first_k_zeros(h.finalize(), d):
            return x
        x += 1


# Verifies the puzzle
def verify_puzzle(ns, nc, x, d):
    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h.update(ns)
    h.update(nc)
    h.update(bytes(x))
    if not __is_first_k_zeros(h.finalize(), d):
        raise exceptions.InvalidSolutionException()


def encrypt_payload(skey, iv, payload):
    encryptor = ciphers.Cipher(algorithms.AES(skey), mode=modes.GCM(iv),
                               backend=default_backend()).encryptor()
    encryptor.authenticate_additional_data("")  # Should Think About This
    ciphertext = encryptor.update(payload) + encryptor.finalize()
    return encryptor.tag, ciphertext


def decrypt_payload(skey, iv, tag, payload):
    decryptor = ciphers.Cipher(algorithms.AES(skey), mode=modes.GCM(iv, tag),
                               backend=default_backend()).decryptor()
    decryptor.authenticate_additional_data("")  # Should Think About This
    plaintext = decryptor.update(payload) + decryptor.finalize()
    return plaintext


def encrypt_key(public_key, key):
    ciphertext = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None))
    return ciphertext


def decrypt_key(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None))
    return plaintext


def sign_stuff(private_key, stuff):
    signature = private_key.sign(
        stuff,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA512()),
            salt_length=padding.PSS.MAX_LENGTH), hashes.SHA512())
    return signature


def __is_first_k_zeros(str, k):
    first_k = str[:k]
    for ch in first_k:
        if ord(ch) != 0:
            return False
    return True


# n1 and n2 are nonces generated by urandom
def __xor(n1, n2):
    xored = ""
    for i in xrange(len(n1)):
        xored += chr(ord(n1[i]) ^ ord(n2[i]))
    return xored


# Basically getting g^ab mod p
def __get_shared_secret(alice_dh_private_key, bob_dh_public_key):
    return alice_dh_private_key.exchange(ec.ECDH(), bob_dh_public_key)


# Salting and Hashing, Added Salt to start of string
def __salt_and_hash(str, salt):
    h = hashes.Hash(hashes.SHA512(), backend=default_backend())
    h.update(salt)
    h.update(str)
    return h.finalize()


if __name__ == "__main__":
    private_key, pub = generate_dh_pair()
    print private_key.public_bytes(encoding=serialization.Encoding.DER,
                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)
