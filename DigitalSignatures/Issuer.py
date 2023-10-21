import base64
import binascii
import json
import requests
import time
from GenerateKeyPair import create_public_private_key_pair
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# ids are unique for each VC.

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
        "revocationListIndex": "0",
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


revocation_list = {}


def get_signature():
    # URL of the Issuer's endpoint
    holder_url = 'http://127.0.0.1:5000/get_signature'

    # Make a GET request to fetch the data
    response = requests.get(holder_url)
    with open("data.txt", "r") as data_file:
        data = data_file.readline()
    message = data.encode('utf-8')

    if response.status_code == 200:
        response_data = response.json()
        signature = response_data['signature']
        with open("public_key.txt", "r") as pk_file:
            h_pk = pk_file.readline()
        print(h_pk)
        h_pk_bytes = bytes.fromhex(h_pk)
        verification_key = serialization.load_pem_public_key(
            h_pk_bytes, backend=default_backend()
        )
        try:
            decoded_signature = bytes.fromhex(signature)
            verification_key.verify(decoded_signature, message)
            print("Signature is valid. Public key is verified.")
        except Exception as e:
            print("Signature verification failed:", e)

    else:
        print("Failed to fetch data. Status code:", response.status_code)


def sign_vc():
    start_time = time.time()
    get_signature()
    with open("public_key.txt", "r") as pk_file:
        h_pk = pk_file.readline()
    h_pk_bytes = bytes.fromhex(h_pk)
    vc['credentialSubject']['id'] = base64.b64encode(h_pk_bytes).decode('utf-8')

    # Sign the verifiable credential
    private_key_pem, public_key_pem = create_public_private_key_pair()
    with open('issuer_pk.txt', 'w') as file:
        file.write(binascii.hexlify(public_key_pem).decode('utf-8'))
    with open('issuer_sk.txt', 'w') as file:
        file.write(binascii.hexlify(private_key_pem).decode('utf-8'))
    print(public_key_pem)
    print(type(public_key_pem))
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend()
    )

    issuer_pk_base64 = base64.b64encode(public_key_pem).decode('utf-8')
    print("issuer pk base 64", issuer_pk_base64)

    # Serialize the compact_vc to a JSON string
    signing_input = json.dumps(vc, separators=(',', ':'), sort_keys=True)

    # Sign the serialized input
    signature = private_key.sign(
        signing_input.encode('utf-8')
    )

    # Encode the signature as base64
    encoded_signature = signature.hex()

    vc['proof'] = {
        "type": "Ed25519Signature2018",
        "created": "2023-08-23T12:34:56Z",
        "verificationMethod": issuer_pk_base64,
        "proofPurpose": "assertionMethod",
        "jws": encoded_signature
    }

    # add vc with 0 value in revocation list
    revocation_list[0] = 0
    with open("revocation_list.txt", 'w') as file:
        file.write(str(revocation_list))

    revocation_data_dict = {str(key): value for key, value in revocation_list.items()}

    # Convert the dictionary to a JSON string
    revocation_data_json = json.dumps(revocation_data_dict, separators=(',', ':'), sort_keys=True)

    # Encode the JSON string to Base64
    encoded_list = base64.b64encode(revocation_data_json.encode('utf-8')).decode('utf-8')

    RevocationList["credentialSubject"]["encodedList"] = encoded_list

    signing_list = json.dumps(RevocationList, separators=(',', ':'), sort_keys=True)

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

    # Serialize the verifiable credential
    vc_json = json.dumps(vc, indent=2)
    print(vc_json)

    # Serialize Revocation List
    rl_json = json.dumps(RevocationList, indent=2)
    print(rl_json)

    with open("revocation_list.txt", 'w') as file:
        file.write(rl_json)

    end_time = time.time()
    elapsed_time = end_time - start_time
    print("Time required to sign VC: ", elapsed_time)

    return vc_json
