from datetime import datetime, timedelta

from flask import Flask, request, jsonify, abort, redirect, make_response
from flask_cors import CORS
from firebase_util import *
from rsa_util import RSA_Util
from enum import Enum

app = Flask(__name__)
cors = CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)  # fixme change this.

fb_util = FirebaseUtil()

INVALID_GET_MESSAGE = "Invalid get"
INVALID_POST_MESSAGE = "Invalid post"


@app.route("/")
def ping():
    return jsonify({'status': 'success'})


@app.route("/register-door-lock", methods=['POST'])
def register_door_lock():  # todo protect this
    args = request.json

    mac = args["MAC"] if args["MAC"] else None
    ip = args["ip_address"] if args["ip_address"] else None
    pubkey = args["pubkey"] if args["pubkey"] else None

    if not mac or not ip or not pubkey:
        return jsonify({'status': 'error', 'code': 400, 'msg': 'Missing arguments.'})

    mac = mac.lower()

    door = {
        "MAC": mac,
        "ip_address": ip,
        "pubkey": pubkey
    }

    fb_util.set_data(f"doors/{mac}", door)

    return jsonify({'status': 'success', 'door': door})


@app.route("/register-invite", methods=['POST'])
def register_invite():
    args = request.json
    signature = args["signature"] if args["signature"] else None

    if not signature:
        return jsonify({'status': 'error', 'code': 403, 'msg': 'Message not signed'})

    print(signature)
    print(args["data"])


    rsa = RSA_Util("public_key.pem")
    if not rsa.is_signature_valid(args["data"], signature):
        return jsonify({'status': 'error', 'code': 403, 'msg': 'Invalid signature'})

    data = args["data"] if args["data"] else None

    if not data:
        return jsonify({'status': 'error', 'code': 400, 'msg': 'Invalid data'})

    print(data)
    return jsonify({'status': 'success'})

    # door_mac = data["doorMAC"] if data["doorMAC"] else None
    # expiration = data["expiration"] if data["expiration"] else None
    # user_type = data["type"] if data["type"] else None
    # valid_from = data["valid_from"] if data["valid_from"] else None
    # valid_until = data["valid_until"] if data["valid_until"] else None


@app.route("/redeem-invite", methods=['POST'])
def redeem_invite():  # todo protect this
    args = request.json

    id_token = args["id_token"] if args["id_token"] else None
    invite = args["invite"] if args["invite"] else None

    if not id_token:
        return jsonify({'status': 'error', 'code': 403, 'msg': 'No Id Token'})

    if not check_if_user(id_token):
        return jsonify({'status': 'error', 'code': 403, 'msg': 'Invalid Id Token'})

    if not invite:
        return jsonify({'status': 'error', 'code': 400, 'msg': 'No invite'})

    user_id = id_token  # fixme change this to acctualy get user_id form id_token

    # mac = mac.lower()
    #
    # door = {
    #     "MAC": mac,
    #     "ip_address": ip,
    #     "pubkey": pubkey
    # }
    #
    # fb_util.set_data(f"doors/{mac}", door)

    return jsonify({'status': 'success'})


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
