import requests
from VRFLibrary import crypto_vrf_prove
import binascii
from VRFLibrary import crypto_vrf_keypair, convert_from_hex


def calculate_credential_hash():
    vc_id_str = receive_vc_id()
    vc_id = bytes(vc_id_str, 'utf-8')
    h_pk, h_sk = create_keypair()
    vc_proof = crypto_vrf_prove(h_sk, vc_id)
    print("vc_proof", vc_proof)
    return vc_proof


def create_keypair():
    pk, sk = crypto_vrf_keypair()
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


def receive_challenge():
    verifier_url = 'http://127.0.0.1:5000/random_challenge'

    # Make a GET request to fetch the id
    response = requests.get(verifier_url)

    if response.status_code == 200:
        response_data = response.json()
        received_challenge = response_data['challenge']

        print("Received challenge:", received_challenge)
        return received_challenge


def calculate_proof():
    challenge = receive_challenge()
    print("challenge", challenge)
    challenge_b = bytes(str(challenge), 'utf-8')
    with open("holder_wallet/private_key.txt", 'r') as file:
        h_sk = file.readline()
    print("h_sk", h_sk)
    sk = convert_from_hex(h_sk,64)
    proof = crypto_vrf_prove(sk, challenge_b)
    return proof



