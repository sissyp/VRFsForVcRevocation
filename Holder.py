import requests
from VRFLibrary import crypto_vrf_prove, crypto_vrf_secretkeybytes
import random
from VRFLibrary import convert_from_hex


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
    # receive challenge from Verifier
    challenge = receive_challenge()
    print("challenge", challenge)
    challenge_str = str(challenge)

    random_number = random.randint(0, 100)
    with open("holder_wallet/private_keys.txt", 'r') as file:
        h_sks = file.readlines()
    h_sk = h_sks[random_number]
    with open("holder_wallet/private_key.txt", 'w') as file:
        file.write(h_sk.strip())
    print("h_sk", h_sk.strip())
    with open("public_keys.txt", 'r') as file:
        h_pks = file.readlines()
    h_pk = h_pks[random_number]
    with open("public_key.txt", 'w') as file:
        file.write(h_pk.strip())
    print("h_pk", h_pk.strip())

    sk = convert_from_hex(h_sk, 64)
    vc_id_str = receive_vc_id()
    concat = vc_id_str + challenge_str
    concat_b = bytes(concat, 'utf-8')
    proof = crypto_vrf_prove(sk, concat_b)
    return proof


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
