import base64
import random

from flask import Flask, jsonify
from Issuer import sign_vc, credential_type
from VerifiablePresentation import create_verifiable_presentation

app = Flask(__name__)


# Issuer sends credential id to a Holder
@app.route('/get_id', methods=['GET'])
def get_id():
    # id which corresponds to the type of the credential
    type_id = credential_type()
    return jsonify(credential_id=type_id)


# Issuer sends a VC to a Holder
@app.route('/get_vc', methods=['GET'])
def get_vc():
    # Issuer's signed VC
    signed_vc = sign_vc()
    return jsonify(signed_vc=signed_vc)


# Verifier sends random challenge to the Holder
@app.route('/random_challenge', methods=['GET'])
def random_challenge():
    random_number = random.randint(1, 1000)
    filename = "challenge.txt"
    with open(filename, 'w') as file:
        file.write(str(random_number))
    return jsonify(challenge=random_number)


# Verifier receives a VP from a Holder
@app.route('/receive_vp', methods=['GET'])
def receive_vp():
    # Holder's signed VP an public key
    signed_vp = create_verifiable_presentation()
    return jsonify(signed_vp=signed_vp)


if __name__ == '__main__':
    app.run(debug=True)
