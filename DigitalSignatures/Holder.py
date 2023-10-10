import base64
import binascii
import requests

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from GenerateKeyPair import create_public_private_key_pair


def create_keypair():
    sk, pk = create_public_private_key_pair()
    print("Public Key:", binascii.hexlify(pk).decode('utf-8'))
    print("Secret Key:", binascii.hexlify(sk).decode('utf-8'))
    print("sk", sk)
    print("pk", pk)
    pk_path = "public_key.txt"
    sk_path = "holder_wallet/private_key.txt"
    with open(pk_path, 'w') as file:
        file.write(binascii.hexlify(pk).decode('utf-8'))
    with open(sk_path, 'w') as file:
        file.write(binascii.hexlify(sk).decode('utf-8'))
    return pk, sk


def receive_data():
    create_keypair()
    # URL of the Issuer's endpoint
    issuer_url = 'http://127.0.0.1:5000/receive_data_to_sign'

    # Make a GET request to fetch the data
    response = requests.get(issuer_url)

    if response.status_code == 200:
        response_data = response.json()
        message = response_data['data']
        message_bytes = message.encode('utf-8')
        with open("holder_wallet/private_key.txt", "r") as sk_file:
            h_sk = sk_file.readline()
        print("h_sk", h_sk)
        try:
            bytes_object = bytes.fromhex(h_sk)
            print("bytes_object", bytes_object)

            private_key = serialization.load_pem_private_key(
                bytes_object, password=None, backend=default_backend()
            )

            # Sign the serialized input
            signature = private_key.sign(message_bytes)
            encoded_signature = signature.hex()
            print(encoded_signature)
            return encoded_signature
        except ValueError as e:
            print("Error:", e)

    else:
        print("Failed to fetch data. Status code:", response.status_code)
