import base64
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


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
def revoke_vc(index):
    revocation_list[index] = 1
    with open("issuer_pk.txt", "r") as pk_file:
        issuer_pk = pk_file.readline()
    with open("issuer_sk.txt", "r") as sk_file:
        issuer_sk = sk_file.readline()

    revocation_data_dict = {str(key): value for key, value in revocation_list.items()}

    # Convert the dictionary to a JSON string
    revocation_data_json = json.dumps(revocation_data_dict, separators=(',', ':'), sort_keys=True)

    # Encode the JSON string to Base64
    encoded_list = base64.b64encode(revocation_data_json.encode('utf-8')).decode('utf-8')

    RevocationList["credentialSubject"]["encodedList"] = encoded_list

    signing_list = json.dumps(RevocationList, separators=(',', ':'), sort_keys=True)
    issuer_sk_bytes = bytes.fromhex(issuer_sk)
    private_key = serialization.load_pem_private_key(
        issuer_sk_bytes, password=None, backend=default_backend()
    )
    issuer_pk_bytes = bytes.fromhex(issuer_pk)
    issuer_pk_base64 = base64.b64encode(issuer_pk_bytes).decode('utf-8')

    # Sign the serialized input
    signature = private_key.sign(
        signing_list.encode('utf-8')
    )

    # Encode the signature as base64
    encoded_list_signature = signature.hex()

    RevocationList['proof'] = {
        "type": "Ed25519Signature2018",
        "created": "2023-08-23T12:34:56Z",
        "verificationMethod": issuer_pk_base64,
        "proofPurpose": "assertionMethod",
        "jws": encoded_list_signature
    }

    # Serialize Revocation List
    rl_json = json.dumps(RevocationList, indent=2)
    print(rl_json)

    with open("revocation_list.txt", 'w') as file:
        file.write(rl_json)
    encoded_rl = RevocationList["credentialSubject"]["encodedList"]
    decoded_list_bytes = base64.b64decode(encoded_rl)

    # Convert the bytes to a JSON string
    decoded_list_json = decoded_list_bytes.decode('utf-8')

    # Parse the JSON string into a Python dictionary
    revocation_data = json.loads(decoded_list_json)
    print(revocation_data)


revoke_vc(0)

