import ast
import base64
import binascii
import time

import requests
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from VRFLibrary import crypto_vrf_verify, convert_from_hex, crypto_vrf_proof_to_hash
from Issuer import get_revocation_hash_table


def receive_vp():
    start_time = time.time()
    # URL of the holder's endpoint
    holder_url = 'http://127.0.0.1:5000/receive_vp'

    # Make a GET request to fetch the VP
    response = requests.get(holder_url)

    if response.status_code == 200:
        response_data = response.json()
        received_vp_str = response_data['signed_vp']
        received_vp = json.loads(received_vp_str)

        print("Received VP:", received_vp)

        # Verify the proofs
        try:
            pop_hex = received_vp['proof']['proofOfPossession']
            proof_hex = received_vp['proof']['proof']
            vc_hash = received_vp['verifiableCredential']['credentialSubject']['id']
            credential_id = received_vp['verifiableCredential']['id']
            credential_id_b = bytes(credential_id, 'utf-8')
            pk_hex = received_vp['proof']['verificationMethod']

            challenge_file = "challenge.txt"
            with open(challenge_file, 'r') as file:
                challenge = file.readline()

            challenge_b = bytes(challenge, 'utf-8')
            pop = convert_from_hex(pop_hex, 80)
            proof = convert_from_hex(proof_hex, 80)
            pk = convert_from_hex(pk_hex, 32)

            pop_hash = crypto_vrf_proof_to_hash(pop)
            output_proof = crypto_vrf_verify(pk, proof, credential_id_b)
            output_pop = crypto_vrf_verify(pk, pop, challenge_b)

            pop_hash_hex = binascii.hexlify(pop_hash).decode('utf-8')
            output_pop_hex = binascii.hexlify(output_pop).decode('utf-8')
            output_proof_hex = binascii.hexlify(output_proof).decode('utf-8')
            print("output_pop_hex", output_pop_hex)
            print("output_proof_hex", output_proof_hex)
            print("vc_hash", vc_hash)
            print("pop_hash", pop_hash_hex)

            if output_pop_hex == pop_hash_hex and output_proof_hex == vc_hash:

                received_vc = received_vp['verifiableCredential']

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
                    received_vc['proof'] = received_proof
                except Exception as e:
                    print("Signature verification failed:", e)

                # check revocation status
                with open("revocation_list.txt", "r") as file:
                    revocation_list = file.read()

                revocation_credential = json.loads(revocation_list)
                vc_revocation_list = received_vc['credentialStatus']["revocationListCredential"]
                revocation_list_name = revocation_credential["id"]

                if vc_revocation_list == revocation_list_name:
                    received_proof_rl = revocation_credential['proof']
                    encoded_rl_sig = revocation_credential['proof']['jws']

                    # Remove the proof section before verification
                    del revocation_credential['proof']

                    # Serialize the VC without the proof
                    rl_without_proof_json = json.dumps(revocation_credential, separators=(',', ':'), sort_keys=True)

                    # Verify the signature
                    try:
                        decoded_signature = bytes.fromhex(encoded_rl_sig)
                        verification_key.verify(
                            decoded_signature,
                            rl_without_proof_json.encode('utf-8')
                        )
                        print("Signature of revocation list is valid.")
                        revocation_credential['proof'] = received_proof_rl
                    except Exception as e:
                        print("Signature verification of revocation list failed:", e)

                    encoded_rl = revocation_credential["credentialSubject"]["encodedList"]
                    decoded_list_bytes = base64.b64decode(encoded_rl)

                    # Convert the bytes to a JSON string
                    decoded_list_json = decoded_list_bytes.decode('utf-8')

                    # Parse the JSON string into a Python dictionary
                    revocation_data = json.loads(decoded_list_json)

                    if revocation_data[vc_hash] == 0:
                        print("VRF proofs are valid.\n ")
                        print("VRF revocation status is checked.\n")
                        print("VP is verified.\n")
                        end_time = time.time()
                        elapsed_time = end_time - start_time
                        print("Time required to verify a VP: ", elapsed_time)
                    else:
                        print("There is at least one revoked VC.")
            else:
                print("Proofs are not valid.")
        except Exception as e:
            print("Verification failed:", e)
    else:
        print("Failed to fetch VP. Status code:", response.status_code)


receive_vp()
