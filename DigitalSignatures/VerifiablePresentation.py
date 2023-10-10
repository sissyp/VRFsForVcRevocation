import base64
import json
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def create_verifiable_presentation():
    start_time = time.time()
    # create an example Verifiable Presentation
    with open("holder_wallet/UniversityDegreeCredential.json", "r") as vc1_file:
        vc1 = json.load(vc1_file)

    # add other VCs
    # with open("holder_wallet/vc_alumni_of.json", "r") as vc2_file:
    # vc2 = json.load(vc2_file)

    vp = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.example.com/contexts/examples-v1.jsonld"
        ],
        "type": ["VerifiablePresentation"],
        "verifiableCredential": vc1
    }

    with open("public_key.txt", "r") as pk_file:
        h_pk = pk_file.readline()

    with open("holder_wallet/private_key.txt", "r") as sk_file:
        h_sk = sk_file.readline()

    # calculate proof that the Holder possesses the credential
    print("holder sk", h_sk)
    h_sk_bytes = bytes.fromhex(h_sk)
    print("bytes", h_sk_bytes)

    private_key = serialization.load_pem_private_key(
        h_sk_bytes, password=None, backend=default_backend()
    )
    h_pk_bytes = bytes.fromhex(h_pk)
    holder_pk_base64 = base64.b64encode(h_pk_bytes).decode('utf-8')

    # Serialize the compact_vc to a JSON string
    signing_input = json.dumps(vp, separators=(',', ':'), sort_keys=True)

    # Sign the serialized input
    signature = private_key.sign(
        signing_input.encode('utf-8')
    )

    # Encode the signature as base64
    encoded_signature = signature.hex()

    vp['proof'] = {
        "type": "Ed25519Signature2018",
        "created": "2023-08-23T12:34:56Z",
        "verificationMethod": holder_pk_base64,
        "proofPurpose": "assertionMethod",
        "jws": encoded_signature
    }

    # Serialize the verifiable credential
    vp_json = json.dumps(vp, indent=2)
    print(vp_json)
    end_time = time.time()

    # Calculate elapsed time
    elapsed_time = end_time - start_time
    print("Time required to create a VP: ", elapsed_time)
    return vp_json
