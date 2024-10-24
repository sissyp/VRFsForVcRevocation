import binascii
import requests
from VRFLibrary import crypto_vrf_keypair, crypto_vrf_prove


def calculate_proofs():
    pk_path = "public_keys.txt"
    sk_path = "holder_wallet/private_keys.txt"
    proofs_path = "proofs.txt"
    vc_id_str = receive_vc_id()
    vc_id_b = bytes(vc_id_str, 'utf-8')

    for i in range(100):
        pk, sk = crypto_vrf_keypair()
        with open(pk_path, 'a') as file:
            file.write(binascii.hexlify(pk).decode('utf-8'))
            file.write('\n')
        with open(sk_path, 'a') as file:
            file.write(binascii.hexlify(sk).decode('utf-8'))
            file.write('\n')
        proof = crypto_vrf_prove(sk, vc_id_b)
        with open(proofs_path, 'a') as file:
            file.write(binascii.hexlify(proof).decode('utf-8'))
            file.write('\n')


def receive_vc_id():
    # URL of the issuer's endpoint
    issuer_url = 'http://127.0.0.1:5000/get_id'

    # Make a GET request to fetch the id
    response = requests.get(issuer_url)

    if response.status_code == 200:
        response_data = response.json()
        received_id = response_data['credential_id']

        print("Received id:", received_id)
        return received_id


calculate_proofs()
