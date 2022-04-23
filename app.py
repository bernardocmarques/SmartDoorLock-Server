import base64
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, abort, redirect, make_response
from flask_cors import CORS
from firebase_util import *
from rsa_util import RSA_Util
from enum import Enum

os.chdir(os.path.dirname(__file__))

app = Flask(__name__)
cors = CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)  # fixme change this.

fb_util = FirebaseUtil()

INVALID_GET_MESSAGE = "Invalid get"
INVALID_POST_MESSAGE = "Invalid post"


@app.route("/")
def ping():
    return jsonify({'success': True})


@app.route("/register-door-lock", methods=['POST'])
def register_door_lock():  # todo protect this
    args = request.json

    mac = args["MAC"] if args["MAC"] else None
    ip = args["ip_address"] if args["ip_address"] else None
    pubkey = args["pubkey"] if args["pubkey"] else None

    if not mac or not ip or not pubkey:
        return jsonify({'success': False, 'code': 400, 'msg': 'Missing arguments.'})

    mac = mac.lower()

    door = {
        "MAC": mac,
        "ip_address": ip,
        "pubkey": pubkey
    }

    fb_util.set_data(f"doors/{mac}", door)

    return jsonify({'success': True, 'door': door})


@app.route("/register-invite", methods=['POST'])
def register_invite():
    args = request.json
    signature = args["signature"] if args["signature"] else None

    if not signature:
        return jsonify({'success': False, 'code': 403, 'msg': 'Message not signed'})

    rsa = RSA_Util("public_key.pem")
    if not rsa.is_signature_valid(args["data"], signature):
        return jsonify({'success': False, 'code': 403, 'msg': 'Invalid signature'})

    data = args["data"] if args["data"] else None

    if not data:
        return jsonify({'success': False, 'code': 400, 'msg': 'Invalid data'})

    data_dict = json.loads(data)
    data_dict["smart_lock_MAC"] = data_dict["smart_lock_MAC"].upper()

    if data_dict.get("weekdays_str"):
        data_dict["weekdays"] = [int(i) for i in data_dict["weekdays_str"]]
        del data_dict["weekdays_str"]

    invite_id = generate_random_id(32)

    fb_util.set_data(f"invites/{invite_id}", data_dict)

    invite_code = base64.b64encode(f'{data_dict["smart_lock_MAC"]} {invite_id}'.encode()).decode()

    return jsonify({'success': True, 'inviteID': invite_code})


@app.route("/request-user-authorization", methods=['POST'])
def request_user_authorization():
    args = request.json
    signature = args["signature"] if args["signature"] else None

    if not signature:
        return jsonify({'success': False, 'code': 403, 'msg': 'Message not signed'})

    rsa = RSA_Util("public_key.pem")
    if not rsa.is_signature_valid(args["data"], signature):
        return jsonify({'success': False, 'code': 403, 'msg': 'Invalid signature'})

    data = args["data"] if args["data"] else None

    if not data:
        return jsonify({'success': False, 'code': 400, 'msg': 'Invalid data'})

    data_dict = json.loads(data)
    mac = data_dict["smart_lock_MAC"].upper()
    user_id = data_dict["user_id"]

    response = fb_util.set_data(f'authorizations/{user_id}/{mac}', data_dict)

    return jsonify({'success': True, 'data': response})


@app.route("/redeem-invite", methods=['POST'])
def redeem_invite():  # todo protect this and also prevent multiple requests
    args = request.json

    id_token = args["id_token"] if args["id_token"] else None
    invite_id = args["invite_id"] if args["invite_id"] else None
    master_key_encrypted_lock = args["master_key_encrypted_lock"] if args["master_key_encrypted_lock"] else None

    if not id_token:
        return jsonify({'success': False, 'code': 403, 'msg': 'No Id Token'})

    # if not check_if_user(id_token):# todo protect this
    #     return jsonify({'success': False, 'code': 403, 'msg': 'Invalid Id Token'})

    if not invite_id:
        return jsonify({'success': False, 'code': 400, 'msg': 'No invite id'})

    user_id = id_token  # fixme change this to acctualy get user_id form id_token

    invite = fb_util.get_data(f"invites/{invite_id}")

    if not invite:
        return jsonify({'success': False, 'code': 400, 'msg': 'Invalid invite'})

    authorization = {
        "user_id": user_id,
        "smart_lock_MAC": invite["smart_lock_MAC"],
        "type": invite["type"],
        "master_key_encrypted_lock": master_key_encrypted_lock
    }

    if invite["type"] == 2 or invite["type"] == 3:
        authorization["valid_from"] = invite["valid_from"]
        authorization["valid_until"] = invite["valid_until"]

    if invite["type"] == 3:
        authorization["weekdays"] = invite["weekdays"]

    if invite["type"] == 4:
        authorization["one_day"] = invite["one_day"]

    fb_util.delete_key(f"invites/{invite_id}")
    fb_util.set_data(f"authorizations/{user_id}/{authorization['smart_lock_MAC']}", authorization)

    return jsonify({'success': True})


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')