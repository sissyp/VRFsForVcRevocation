import binascii

import requests
import json
from VRFLibrary import crypto_vrf_proof_to_hash, crypto_vrf_verify, convert_from_hex


def receive_vc():
    # URL of the issuer's endpoint
    issuer_url = 'http://127.0.0.1:5000/get_vc'

    # Make a GET request to fetch the VC
    response = requests.get(issuer_url)

    if response.status_code == 200:
        response_data = response.json()
        received_vc_str = response_data['signed_vc']
        received_vc = json.loads(received_vc_str)

        print("Received VC:", received_vc)

        # Extract the Issuer's proof from the received VC
        issuer_proof = received_vc['proof']['vrfProof']

        issuer_pk_pem = received_vc['proof']['verificationMethod']

        # Load the issuer's public key for verification
        proof = convert_from_hex(issuer_proof, 80)
        pk = convert_from_hex(issuer_pk_pem, 32)
        vc_id = received_vc['id']
        vc_id_b = bytes(vc_id, 'utf-8')
        print("Verification key in pem format", pk)
        hash_from_issuer_proof = crypto_vrf_proof_to_hash(proof)
        output = crypto_vrf_verify(pk, proof, vc_id_b)

        hash_from_issuer_proof_hex = binascii.hexlify(hash_from_issuer_proof).decode('utf-8')
        output_hex = binascii.hexlify(output).decode('utf-8')
        print("hash from vrf issuer", hash_from_issuer_proof_hex)
        print("output issuer", output_hex)

        if hash_from_issuer_proof_hex == output_hex:
            print("Issuer's VRF proof has been verified")
            # Store the VC in the Holder's wallet
            vc_name = received_vc['type'][1]
            vc_filename = f"holder_wallet/{vc_name}.json"
            with open(vc_filename, "w") as vc_file:
                json.dump(received_vc, vc_file, indent=2)
            print(f"VC stored in {vc_filename}")
        else:
            print("Failed to verify Issuer's VRF proof")

    else:
        print("Failed to fetch VC. Status code:", response.status_code)


receive_vc()
