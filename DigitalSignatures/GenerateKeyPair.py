from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def create_public_private_key_pair():

    # Generate a new Ed25519 (Edwards-curve Digital Signature Algorithm) key pair
    private_key = ed25519.Ed25519PrivateKey.generate()

    # Serialize the private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Extract the corresponding public key
    public_key = private_key.public_key()

    # Serialize the public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Print the private and public keys
    # print("Private Key:")
    # print(private_key_pem.decode('utf-8'))

    # print("\nPublic Key:")
    # print(public_key_pem.decode('utf-8'))

    return private_key_pem, public_key_pem
