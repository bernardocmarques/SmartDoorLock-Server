import base64
from datetime import datetime, timedelta
from os import path, listdir

from flask import Flask, request, jsonify, abort, redirect, make_response, send_file
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

''' ---------------------------------------- '''
''' ----------------- Open ----------------- '''
''' ---------------------------------------- '''


@app.route("/")
def ping():
    return jsonify({'success': True})


@app.route("/get-icon", methods=['GET'])
def get_icon():
    args = request.args

    icon_id = args.get("icon_id") if args.get("icon_id") else None

    if not icon_id:
        return "icon_id not provided", 404

    filename = f"lock_icons/{icon_id}.png"
    file_exists = path.exists(filename)

    if not file_exists:
        return f"Icon with ID \"{icon_id}\" does no exist", 404

    return send_file(filename, mimetype='image/png')


@app.route("/get-all-icons", methods=['GET'])
def get_all_icon():
    files = listdir('lock_icons')

    icon_ids = []

    for file in files:
        if ".png" in file:
            file = file.replace(".png", "")
            icon_ids.append(file)

    return jsonify({'success': True, 'icons': icon_ids})


''' ---------------------------------------- '''
''' ----------------- Lock ----------------- '''
''' ---------------------------------------- '''


@app.route("/get-username", methods=['GET'])
def get_username():
    args = request.args

    id_token = args.get("id_token") if args.get("id_token") else None

    if not id_token:
        return jsonify({'success': False, 'code': 403, 'msg': 'No Id Token'})

    if not check_if_user(id_token):
        return jsonify({'success': False, 'code': 403, 'msg': 'Invalid Id Token'})

    username = fb_util.get_data(f"users/{get_decoded_claims_id_token(id_token).get('uid')}/username")
    if not username:
        username = fb_util.set_random_username(get_decoded_claims_id_token(id_token).get("uid"))

    return jsonify({'success': True, 'username': username})


@app.route("/check-lock-registration-status", methods=['GET'])
def check_lock_registration_status():
    args = request.args

    mac = args.get("MAC") if args.get("MAC") else None

    if not mac:
        return jsonify({'success': False, 'code': 400, 'msg': 'Missing argument MAC.'})

    mac = mac.upper()

    lock_registered = not not fb_util.get_data(f"doors/{mac}")
    lock_with_auths = not not fb_util.get_data(f"authorizations/{mac}")

    if lock_registered and lock_with_auths:
        return jsonify({'success': True, 'status': 2})  # registered and with auths
    elif lock_registered and not lock_with_auths:
        return jsonify({'success': True, 'status': 1})  # just registered
    elif not lock_registered and not lock_with_auths:
        return jsonify({'success': True, 'status': 0})  # just not registered
    else:
        return jsonify({'success': False, 'code': 500, 'msg': 'Unknown state'})  # just not registered


@app.route("/register-door-lock", methods=['POST'])
def register_door_lock():  # todo protect this (verificate certificate and check if for right mac)
    args = request.json

    mac = args.get("MAC") if args.get("MAC") else None
    certificate = args.get("certificate") if args.get("certificate") else None

    if not mac or not certificate:
        return jsonify({'success': False, 'code': 400, 'msg': 'Missing arguments.'})

    mac = mac.upper()

    door = {
        "MAC": mac,
        "certificate": certificate
    }

    fb_util.set_data(f"doors/{mac}", door)

    return jsonify({'success': True})


@app.route("/get-door-certificate", methods=['GET'])
def get_door_certificate():
    args = request.args
    id_token = args.get("id_token") if args.get("id_token") else None
    smart_lock_mac = args.get("smart_lock_mac").upper() if args.get("smart_lock_mac") else None
    print(id_token)
    if not id_token:
        return jsonify({'success': False, 'code': 403, 'msg': 'No Id Token'})

    if not check_if_user(id_token):
        return jsonify({'success': False, 'code': 403, 'msg': 'Invalid Id Token'})

    if not smart_lock_mac:
        return jsonify({'success': False, 'code': 400, 'msg': 'No smart_lock_mac'})

    certificate = fb_util.get_data(f"doors/{smart_lock_mac}/certificate")

    return jsonify({'success': True, 'certificate': certificate})


# @app.route("/create-first-invite", methods=['POST'])
# def register_invite():
#     args = request.json
#     signature = args.get("signature") if args.get("signature") else None
#
#     if not signature:
#         return jsonify({'success': False, 'code': 403, 'msg': 'Message not signed'})
#
#     rsa = RSA_Util("public_key.pem")
#     if not rsa.is_signature_valid(args.get("data"), signature):
#         return jsonify({'success': False, 'code': 403, 'msg': 'Invalid signature'})
#
#     data = args.get("data") if args.get("data") else None
#
#     if not data:
#         return jsonify({'success': False, 'code': 400, 'msg': 'Invalid data'})
#
#     data_dict = json.loads(data)
#     data_dict["smart_lock_MAC"] = data_dict["smart_lock_MAC"].upper()
#
#     fb_util.set_data(f"first_invites/{data_dict["smart_lock_MAC"]}", data_dict)
#
#     invite_code = base64.b64encode(f'{data_dict["smart_lock_MAC"]} {invite_id}'.encode()).decode()
#
#     return jsonify({'success': True, 'inviteID': invite_code})


@app.route("/register-invite", methods=['POST'])
def register_invite():
    args = request.json
    signature = args.get("signature") if args.get("signature") else None

    if not signature:
        return jsonify({'success': False, 'code': 403, 'msg': 'Message not signed'})

    rsa = RSA_Util("public_key.pem")
    if not rsa.is_signature_valid(args.get("data"), signature):
        return jsonify({'success': False, 'code': 403, 'msg': 'Invalid signature'})

    data = args.get("data") if args.get("data") else None

    if not data:
        return jsonify({'success': False, 'code': 400, 'msg': 'Invalid data'})

    data_dict = json.loads(data)
    data_dict["smart_lock_MAC"] = data_dict["smart_lock_MAC"].upper()

    if data_dict.get("weekdays_str"):
        data_dict["weekdays"] = [int(i) for i in data_dict["weekdays_str"]]
        del data_dict["weekdays_str"]

    invite_id = generate_random_id(32)

    fb_util.set_data(f"invites/{invite_id}", data_dict)

    ble_addr = fb_util.get_data(f"doors/{data_dict['smart_lock_MAC']}/BLE")

    invite_code = base64.b64encode(f'{invite_id} {data_dict["smart_lock_MAC"]} {ble_addr}'.encode()).decode()

    return jsonify({'success': True, 'inviteID': invite_code})


@app.route("/request-authorization", methods=['POST'])
def request_authorization():
    args = request.json
    signature = args.get("signature") if args.get("signature") else None

    if not signature:
        return jsonify({'success': False, 'code': 403, 'msg': 'Message not signed'})

    rsa = RSA_Util("public_key.pem")
    if not rsa.is_signature_valid(args["data"], signature):
        return jsonify({'success': False, 'code': 403, 'msg': 'Invalid signature'})

    data = args.get("data") if args.get("data") else None

    if not data:
        return jsonify({'success': False, 'code': 400, 'msg': 'Invalid data'})

    data_dict = json.loads(data)
    mac = data_dict["smart_lock_MAC"].upper()
    username = data_dict["username"]

    if not username or not mac:
        return jsonify({'success': False, 'code': 400, 'msg': 'No username or mac'})

    response = fb_util.get_data(f'authorizations/{mac}/{username}')

    print(response)
    print(len(str(response)))

    return jsonify({'success': True, 'data': response})


@app.route("/redeem-invite", methods=['POST'])
def redeem_invite():  # todo protect this and also prevent multiple requests
    args = request.json

    id_token = args.get("id_token") if args.get("id_token") else None
    invite_id = args.get("invite_id") if args.get("invite_id") else None
    master_key_encrypted_lock = args.get("master_key_encrypted_lock") if args.get("master_key_encrypted_lock") else None

    if not id_token:
        return jsonify({'success': False, 'code': 403, 'msg': 'No Id Token'})

    if not check_if_user(id_token):
        return jsonify({'success': False, 'code': 403, 'msg': 'Invalid Id Token'})

    if not invite_id:
        return jsonify({'success': False, 'code': 400, 'msg': 'No invite id'})

    username = fb_util.get_data(f"users/{get_decoded_claims_id_token(id_token).get('uid')}/username")

    invite = fb_util.get_data(f"invites/{invite_id}")

    if not invite:
        return jsonify({'success': False, 'code': 400, 'msg': 'Invalid invite'})

    authorization = {
        "username": username,
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
    fb_util.set_data(f"authorizations/{authorization['smart_lock_MAC']}/{username}", authorization)

    return jsonify({'success': True})


@app.route("/get-user-locks", methods=['GET'])
def get_user_locks():
    args = request.args
    id_token = args.get("id_token") if args.get("id_token") else None

    if not id_token:
        return jsonify({'success': False, 'code': 403, 'msg': 'No Id Token'})

    if not check_if_user(id_token):
        return jsonify({'success': False, 'code': 403, 'msg': 'Invalid Id Token'})

    user_id = get_decoded_claims_id_token(id_token).get('uid')

    locks = fb_util.get_data(f"users/{user_id}/locks")

    if not locks:
        return jsonify({'success': True, 'locks': []})

    return jsonify({'success': True, 'locks': list(locks.values())})


@app.route("/set-user-locks", methods=['POST'])
def set_user_locks():
    args = request.json
    id_token = args.get("id_token") if args.get("id_token") else None
    lock = args.get("lock") if args.get("lock") else {}

    if not id_token:
        return jsonify({'success': False, 'code': 403, 'msg': 'No Id Token'})

    if not check_if_user(id_token):
        return jsonify({'success': False, 'code': 403, 'msg': 'Invalid Id Token'})

    user_id = get_decoded_claims_id_token(id_token).get('uid')

    if not lock:
        return jsonify({'success': False, 'code': 403, 'msg': 'Lock information not provided'})

    lock["BLE"] = lock.get("BLE").upper() if lock.get("BLE") else ""
    lock["MAC"] = lock.get("MAC").upper() if lock.get("MAC") else ""
    lock["id"] = lock.get("id").upper() if lock.get("id") else ""

    fb_util.set_data(f"users/{user_id}/locks/{lock.get('id')}", lock)

    return jsonify({'success': True})


@app.route("/delete-user-lock", methods=['POST'])
def delete_user_locks():
    args = request.json
    id_token = args.get("id_token") if args.get("id_token") else None
    lock_id = args.get("lock_id") if args.get("lock_id") else {}

    if not id_token:
        return jsonify({'success': False, 'code': 403, 'msg': 'No Id Token'})

    if not lock_id:
        return jsonify({'success': False, 'code': 403, 'msg': 'No Lock Id'})

    if not check_if_user(id_token):
        return jsonify({'success': False, 'code': 403, 'msg': 'Invalid Id Token'})

    user_id = get_decoded_claims_id_token(id_token).get('uid')

    fb_util.delete_key(f"users/{user_id}/locks/{lock_id}")

    return jsonify({'success': True})


@app.route("/get-lock-mac", methods=['GET'])
def get_lock_mac():
    args = request.args
    id_token = args.get("id_token") if args.get("id_token") else None
    ble_address = args.get("ble_address") if args.get("ble_address") else None

    if not id_token:
        return jsonify({'success': False, 'code': 403, 'msg': 'No Id Token'})

    if not ble_address:
        return jsonify({'success': False, 'code': 403, 'msg': 'No BLE address'})

    if not check_if_user(id_token):
        return jsonify({'success': False, 'code': 403, 'msg': 'Invalid Id Token'})

    lock = fb_util.get_data_where_child_equal_to(f"doors", "BLE", ble_address)

    if not lock:
        return jsonify(
            {'success': False, 'code': 404, 'msg': f'Could not found Smart Lock with BLE address {ble_address}'})

    return jsonify({'success': True, 'mac': lock["MAC"]})


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
