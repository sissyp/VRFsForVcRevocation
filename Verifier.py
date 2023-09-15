import ast
import binascii

import requests
import json
from VRFLibrary import crypto_vrf_verify, convert_from_hex, crypto_vrf_proof_to_hash
from Issuer import get_revocation_hash_table


def receive_vp():
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

            proof_hash = crypto_vrf_proof_to_hash(proof)
            output_pop = crypto_vrf_verify(pk, pop, credential_id_b)
            output_proof = crypto_vrf_verify(pk, proof, challenge_b)

            proof_hash_hex = binascii.hexlify(proof_hash).decode('utf-8')
            output_pop_hex = binascii.hexlify(output_pop).decode('utf-8')
            output_proof_hex = binascii.hexlify(output_proof).decode('utf-8')
            print("output_pop_hex", output_pop_hex)
            print("output_proof_hex", output_proof_hex)
            print("vc_hash", vc_hash)
            print("proof_hash", proof_hash_hex)

            if output_proof_hex == proof_hash_hex and output_pop_hex == vc_hash:
                # check revocation status
                revocation_hash_table = get_revocation_hash_table()
                revocation_dict = {}
                try:
                    revocation_dict = ast.literal_eval(revocation_hash_table)
                    if isinstance(revocation_dict, dict):
                        print("Successfully converted the string to a dictionary:")
                        print(revocation_dict)
                    else:
                        print("The input string does not represent a valid dictionary.")
                except (SyntaxError, ValueError):
                    print("Failed to convert the input string to a dictionary.")
                print(revocation_dict)
                if vc_hash in revocation_dict:
                    if revocation_dict[vc_hash] == 0:
                        print("VRF proofs are valid.\n ")
                        print("VRF revocation status is checked.\n")
                        print("VP is verified.\n")
                    else:
                        print("There is at least one revoked VC.")
                else:
                    print("VCs not present in hash table.")
            else:
                print("Proofs are not valid.")
        except Exception as e:
            print("Verification failed:", e)
    else:
        print("Failed to fetch VP. Status code:", response.status_code)


receive_vp()
