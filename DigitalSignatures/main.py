from flask import Flask, jsonify

from Holder import receive_data
from Issuer import sign_vc
from VerifiablePresentation import create_verifiable_presentation

app = Flask(__name__)


# Verify Holder's public key
@app.route('/receive_data_to_sign', methods=['GET'])
def receive_data_to_sign():
    data_to_sign = "data to sign"
    path = "data.txt"
    with open(path, 'w') as file:
        file.write(data_to_sign)
    return jsonify(data=data_to_sign)


# Issuer sends a VC to a Holder
@app.route('/get_signature', methods=['GET'])
def get_signature():
    signature = receive_data()
    return jsonify(signature=signature)


# Issuer sends a VC to a Holder
@app.route('/get_vc', methods=['GET'])
def get_vc():
    # Issuer's signed VC
    signed_vc = sign_vc()
    return jsonify(signed_vc=signed_vc)


# Verifier receives a VP from a Holder
@app.route('/receive_vp', methods=['GET'])
def receive_vp():
    # Holder's signed VP an public key
    signed_vp = create_verifiable_presentation()
    return jsonify(signed_vp=signed_vp)


if __name__ == '__main__':
    app.run(debug=True)
