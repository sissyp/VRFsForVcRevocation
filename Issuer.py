import time
import base64
import binascii
import json
from Holder import calculate_credential_hash
from VRFLibrary import crypto_vrf_verify, crypto_vrf_proof_to_hash, convert_from_hex, crypto_vrf_keypair, \
    crypto_vrf_prove

# Create the verifiable credential
# it has an id for credentials of the same type
# e.g., ability to drive

revocation_hash_table = {}

vc = {
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.example.com/contexts/examples-v1.jsonld"
    ],
    "id": "https://example.com/credentials/123",
    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
    "issuer": "did:example:123",
    "issuanceDate": "2023-08-23T12:34:56Z",
    "credentialStatus": {
        "type": "RevocationList2020Status",
        "revocationListCredential": "https://example.com/credentials/status/3"
    },
    "credentialSubject": {
        "degree": {
            "type": "BachelorDegree",
            "name": "Bachelor of Science",
            "university": "Example University"
        }
    }
}

RevocationList = {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/vc-revocation-list-2020/v1"
      ],
      "id": "https://example.com/credentials/status/3",
      "type": ["VerifiableCredential", "RevocationList2020Credential"],
      "issuer": "did:example:123",
      "issued": "2020-04-05T14:27:40Z",
      "credentialSubject": {
        "id": "https://example.com/status/3#list",
        "type": "RevocationList2020"
      }
}


def credential_type():
    return vc['id']


def sign_vc():
    start_time = time.time()
    # verify the Holder's public key
    vc_proof = calculate_credential_hash()
    with open("public_key.txt", "r") as pk_file:
        h_pk = pk_file.readline()
    pk = convert_from_hex(h_pk, 32)
    x = bytes(credential_type(), 'utf-8')
    output = crypto_vrf_verify(pk, vc_proof, x)
    hash_from_proof = crypto_vrf_proof_to_hash(vc_proof)
    print("hash from proof", binascii.hexlify(hash_from_proof).decode('utf-8'))
    print("output", binascii.hexlify(output).decode('utf-8'))

    # create Issuer's keypair
    issuer_pk, issuer_sk = crypto_vrf_keypair()
    with open('issuer_pk.txt', 'w') as file:
        file.write(binascii.hexlify(issuer_pk).decode('utf-8'))
    with open('issuer_sk.txt', 'w') as file:
        file.write(binascii.hexlify(issuer_sk).decode('utf-8'))

    if binascii.hexlify(hash_from_proof).decode('utf-8') == binascii.hexlify(output).decode('utf-8'):

        # add vrf hash to the credential
        vc_hash = binascii.hexlify(hash_from_proof).decode('utf-8')
        vc["credentialSubject"]["id"] = vc_hash

        # check revocation hash table -> if the hash of the vc does not exist
        # then add hash,0 to the hash table
        if vc_hash in revocation_hash_table:
            print("Credential already exists and cannot be re-issued")
        else:
            revocation_hash_table[vc_hash] = 0
            with open("revocation_table.txt", 'w') as file:
                file.write(str(revocation_hash_table))

            # Create Issuer's proof for the VC (similar to signature in a DS system)
            vc_hash_bytes = bytes(vc_hash, 'utf-8')
            issuer_proof = crypto_vrf_prove(issuer_sk, vc_hash_bytes)

            revocation_data_dict = {str(key): value for key, value in revocation_hash_table.items()}

            # Convert the dictionary to a JSON string
            revocation_data_json = json.dumps(revocation_data_dict, separators=(',', ':'), sort_keys=True)

            # Encode the JSON string to Base64
            encoded_list = base64.b64encode(revocation_data_json.encode('utf-8')).decode('utf-8')

            RevocationList["credentialSubject"]["encodedList"] = encoded_list
            encoded_list_bytes = bytes(encoded_list, 'utf-8')
            issuer_proof_rl = crypto_vrf_prove(issuer_sk, encoded_list_bytes)

            issuer_pk_hex = binascii.hexlify(issuer_pk).decode('utf-8')
            issuer_proof_hex = binascii.hexlify(issuer_proof).decode('utf-8')
            issuer_proof_rl_hex = binascii.hexlify(issuer_proof_rl).decode('utf-8')

            RevocationList['proof'] = {
                "type": "Ed25519Signature2018",
                "created": "2023-08-23T12:34:56Z",
                "verificationMethod": issuer_pk_hex,
                "proofPurpose": "assertionMethod",
                "vrfProof": issuer_proof_rl_hex
            }

            vc['proof'] = {
                "type": "Ed25519Signature2018",
                "created": "2023-08-23T12:34:56Z",
                "verificationMethod": issuer_pk_hex,
                "proofPurpose": "assertionMethod",
                "vrfProof": issuer_proof_hex
            }

            # Serialize the verifiable credential
            vc_json = json.dumps(vc, indent=2)
            print(vc_json)
            print(revocation_hash_table)

            # Serialize Revocation List
            rl_json = json.dumps(RevocationList, indent=2)
            print(rl_json)

            with open("revocation_table.txt", 'w') as file:
                file.write(rl_json)

            end_time = time.time()
            elapsed_time = end_time - start_time
            print("Time required to sign a VC: ", elapsed_time)
            return vc_json
    else:
        print("VRF proof not verified by Issuer")
