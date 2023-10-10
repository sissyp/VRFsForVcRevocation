import base64
import requests
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


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

        # Extract the encoded signature from the received VC
        encoded_signature = received_vc['proof']['jws']

        issuer_pk_pem = received_vc['proof']['verificationMethod']

        # Load the issuer's public key for verification
        verification_key_pem = base64.b64decode(issuer_pk_pem)
        print("Verification key in pem format", verification_key_pem)

        verification_key = serialization.load_pem_public_key(
            verification_key_pem, backend=default_backend()
        )

        received_proof = received_vc['proof']

        # Remove the proof section before verification
        del received_vc['proof']

        # Serialize the VC without the proof
        vc_without_proof_json = json.dumps(received_vc, separators=(',', ':'), sort_keys=True)

        # Verify the signature
        try:
            decoded_signature = bytes.fromhex(encoded_signature)
            verification_key.verify(
                decoded_signature,
                vc_without_proof_json.encode('utf-8')
            )
            print("Signature is valid. VC is verified.")

            # Store the VC in the Holder's wallet
            vc_name = received_vc['type'][1]
            vc_filename = f"holder_wallet/{vc_name}.json"
            received_vc['proof'] = received_proof
            with open(vc_filename, "w") as vc_file:
                json.dump(received_vc, vc_file, indent=2)
            print(f"VC stored in {vc_filename}")

        except Exception as e:
            print("Signature verification failed:", e)
    else:
        print("Failed to fetch VC. Status code:", response.status_code)


receive_vc()
