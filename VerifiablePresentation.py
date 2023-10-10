import binascii
import json
import time
from Holder import calculate_proof
from VRFLibrary import crypto_vrf_prove, convert_from_hex


def create_verifiable_presentation():
    start_time = time.time()
    pop = calculate_proof()
    print("proof for challenge", binascii.hexlify(pop).decode('utf-8'))
    pop_hex = binascii.hexlify(pop).decode('utf-8')

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

    credential_id = vc1['id']
    id_b = bytes(credential_id, 'utf-8')
    sk = convert_from_hex(h_sk, 64)
    proof = crypto_vrf_prove(sk, id_b)
    proof_hex = binascii.hexlify(proof).decode('utf-8')

    vp['proof'] = {
        "type": "VRF2023",
        "created": "2023-08-23T12:34:56Z",
        "verificationMethod": h_pk,
        "proofOfPossession": pop_hex,
        "proof": proof_hex
    }

    # Serialize the verifiable presentation
    vp_json = json.dumps(vp, indent=2)
    end_time = time.time()
    elapsed_time = end_time - start_time
    print("Time required to create a VP: ", elapsed_time)

    print(vp_json)
    return vp_json
