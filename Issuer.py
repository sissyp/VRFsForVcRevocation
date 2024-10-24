import time
import base64
import binascii
import json
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
    with open("public_keys.txt", "r") as pk_file:
        h_pks = pk_file.readlines()
    with open("proofs.txt", "r") as proofs_file:
        proofs = proofs_file.readlines()
    vc_type = credential_type()
    vc_type_bytes = bytes(vc_type, 'utf-8')

    for i in range(len(h_pks)):
        pk = convert_from_hex(h_pks[i], 32)
        proof_b = convert_from_hex(proofs[i], 80)

        output = crypto_vrf_verify(pk, proof_b, vc_type_bytes)
        hash_from_proof = crypto_vrf_proof_to_hash(proof_b)

        if binascii.hexlify(hash_from_proof).decode('utf-8') == binascii.hexlify(output).decode('utf-8'):
            print("hash", binascii.hexlify(hash_from_proof).decode('utf-8'))
            print("output", binascii.hexlify(output).decode('utf-8'))

            # check revocation hash table -> if the hash of the vc does not exist
            # then add hash,0 to the hash table
            pk_hex = binascii.hexlify(pk).decode('utf-8')
            if pk_hex in revocation_hash_table:
                print("Credential already exists and cannot be re-issued")
            else:
                revocation_hash_table[pk_hex] = 0
                with open("revocation_table.txt", 'w') as file:
                    file.write(str(revocation_hash_table))
        else:
            print("VRF proof not verified by Issuer")

    # create Issuer's keypair
    issuer_pk, issuer_sk = crypto_vrf_keypair()
    with open('issuer_pk.txt', 'w') as file:
        file.write(binascii.hexlify(issuer_pk).decode('utf-8'))
    with open('issuer_sk.txt', 'w') as file:
        file.write(binascii.hexlify(issuer_sk).decode('utf-8'))

    # Create Issuer's proof for the VC (similar to signature in a DS system)

    issuer_proof = crypto_vrf_prove(issuer_sk, vc_type_bytes)

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
        "type": "VRF2023",
        "created": "2023-08-23T12:34:56Z",
        "verificationMethod": issuer_pk_hex,
        "proofPurpose": "assertionMethod",
        "vrfProof": issuer_proof_rl_hex
    }

    vc['proof'] = {
        "type": "VRF2023",
        "created": "2023-08-23T12:34:56Z",
        "verificationMethod": issuer_pk_hex,
        "proofPurpose": "assertionMethod",
        "vrfProof": issuer_proof_hex
        }

    # Serialize the verifiable credential
    vc_json = json.dumps(vc, indent=2)
    print(vc_json)
    print(len(revocation_hash_table))
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
