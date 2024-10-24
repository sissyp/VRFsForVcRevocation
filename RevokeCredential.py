import base64
import binascii
import json
import time

from VRFLibrary import crypto_vrf_prove, convert_from_hex

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

revocation_list = {}


# revoke a VC by changing the status to 1
def revoke_vc():
    with open("public_keys.txt", 'r') as file:
        h_pks = file.readlines()
    for h_pk in h_pks:
        revocation_list[h_pk.strip()] = 1

    with open("issuer_pk.txt", "r") as pk_file:
        issuer_pk = pk_file.readline()
    with open("issuer_sk.txt", "r") as sk_file:
        issuer_sk = sk_file.readline()
    print(issuer_sk)
    print(type(issuer_sk))
    pk = convert_from_hex(issuer_pk, 32)
    sk = convert_from_hex(issuer_sk, 64)

    revocation_data_dict = {str(key): value for key, value in revocation_list.items()}

    # Convert the dictionary to a JSON string
    revocation_data_json = json.dumps(revocation_data_dict, separators=(',', ':'), sort_keys=True)

    # Encode the JSON string to Base64
    encoded_list = base64.b64encode(revocation_data_json.encode('utf-8')).decode('utf-8')

    RevocationList["credentialSubject"]["encodedList"] = encoded_list
    encoded_list_bytes = bytes(encoded_list, 'utf-8')
    start_time = time.time()
    issuer_proof_rl = crypto_vrf_prove(sk, encoded_list_bytes)
    print("issuer proof rl", issuer_proof_rl)
    issuer_pk_hex = binascii.hexlify(pk).decode('utf-8')
    issuer_proof_rl_hex = binascii.hexlify(issuer_proof_rl).decode('utf-8')

    RevocationList['proof'] = {
        "type": "VRF2023",
        "created": "2023-08-23T12:34:56Z",
        "verificationMethod": issuer_pk_hex,
        "proofPurpose": "assertionMethod",
        "vrfProof": issuer_proof_rl_hex
    }

    # Serialize Revocation List
    rl_json = json.dumps(RevocationList, indent=2)
    print(rl_json)

    with open("revocation_table.txt", 'w') as file:
        file.write(rl_json)

    encoded_rl = RevocationList["credentialSubject"]["encodedList"]
    decoded_list_bytes = base64.b64decode(encoded_rl)

    # Convert the bytes to a JSON string
    decoded_list_json = decoded_list_bytes.decode('utf-8')

    # Parse the JSON string into a Python dictionary
    revocation_data = json.loads(decoded_list_json)
    print(revocation_data)
    end_time = time.time()
    elapsed_time = end_time - start_time
    print("Time required to revoke a VC: ", elapsed_time)


revoke_vc()

