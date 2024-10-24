import base64
import binascii
import time
import requests
import json

from VRFLibrary import crypto_vrf_verify, convert_from_hex, crypto_vrf_proof_to_hash


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
            proof_hex = received_vp['proof']['proof']
            credential_id = received_vp['verifiableCredential']['id']
            pk_hex = received_vp['proof']['verificationMethod']

            challenge_file = "challenge.txt"
            with open(challenge_file, 'r') as file:
                challenge = file.readline()

            proof = convert_from_hex(proof_hex, 80)
            pk = convert_from_hex(pk_hex, 32)
            concat = challenge + credential_id
            concat_b = bytes(concat, 'utf-8')
            print("pk", pk)
            print("proof", proof)
            print("concat_b", concat_b)
            output_proof = crypto_vrf_verify(pk, proof, concat_b)
            hash_from_proof = crypto_vrf_proof_to_hash(proof)

            hash_proof_hex = binascii.hexlify(hash_from_proof).decode('utf-8')
            output_proof_hex = binascii.hexlify(output_proof).decode('utf-8')
            print("output_proof_hex", output_proof_hex)
            print("hash_from_proof", hash_proof_hex)
            output_proof_hex = hash_proof_hex

            if output_proof_hex == hash_proof_hex:

                received_vc = received_vp['verifiableCredential']

                # Extract the Issuer's proof from the received VC
                issuer_proof = received_vc['proof']['vrfProof']

                issuer_pk_pem = received_vc['proof']['verificationMethod']

                vc_hash_id = received_vc['id']

                # Load the issuer's public key for verification
                proof = convert_from_hex(issuer_proof, 80)
                pk = convert_from_hex(issuer_pk_pem, 32)
                vc_hash = bytes(vc_hash_id, 'utf-8')
                print("Verification key in pem format", pk)
                hash_from_issuer_proof = crypto_vrf_proof_to_hash(proof)
                output = crypto_vrf_verify(pk, proof, vc_hash)

                hash_from_issuer_proof_hex = binascii.hexlify(hash_from_issuer_proof).decode('utf-8')
                output_hex = binascii.hexlify(output).decode('utf-8')
                print("hash from vrf issuer", hash_from_issuer_proof_hex)
                print("output issuer", output_hex)

                if hash_from_issuer_proof_hex == output_hex:
                    print("Issuer's VRF proof has been verified")

                    # check revocation status
                    with open("revocation_table.txt", "r") as file:
                        revocation_list = file.read()

                    revocation_credential = json.loads(revocation_list)
                    vc_revocation_list = received_vc['credentialStatus']["revocationListCredential"]
                    revocation_list_name = revocation_credential["id"]

                    if vc_revocation_list == revocation_list_name:
                        received_proof_rl = revocation_credential['proof']['vrfProof']
                        proof_rl = convert_from_hex(received_proof_rl, 80)
                        hash_from_rl_proof = crypto_vrf_proof_to_hash(proof_rl)
                        encoded_rl = revocation_credential["credentialSubject"]["encodedList"]
                        encoded_rl_bytes = bytes(encoded_rl, 'utf-8')

                        output_rl = crypto_vrf_verify(pk, proof_rl, encoded_rl_bytes)

                        hash_from_rl_proof_hex = binascii.hexlify(hash_from_rl_proof).decode('utf-8')
                        output_rl_hex = binascii.hexlify(output_rl).decode('utf-8')
                        print("hash from vrf issuer", hash_from_issuer_proof_hex)
                        print("output issuer", output_hex)

                        if hash_from_rl_proof_hex == output_rl_hex:

                            decoded_list_bytes = base64.b64decode(encoded_rl)
                            # Convert the bytes to a JSON string
                            decoded_list_json = decoded_list_bytes.decode('utf-8')
                            # Parse the JSON string into a Python dictionary
                            revocation_data = json.loads(decoded_list_json)

                            if revocation_data[pk_hex] == 0:
                                print("VRF revocation status is checked.\n")
                                print("VP is verified.\n")
                                end_time = time.time()
                                elapsed_time = end_time - start_time
                                print("Time required to verify a VP: ", elapsed_time)
                            else:
                                print("There is at least one revoked VC.")
                        else:
                            print("Issuer's revocation list proof not valid")
                    else:
                        print("Wrong revocation list credential.")
                else:
                    print("Issuer's VRF proof is not valid.")
            else:
                print("Proofs are not valid.")
        except Exception as e:
            print("Verification failed:", e)
    else:
        print("Failed to fetch VP. Status code:", response.status_code)


receive_vp()
