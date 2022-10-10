import base64
import json
import time
import unittest

import requests
from firebase_admin import auth

import rsa_util
from app import app, create_fb_util, _get_lock_rsa_key
from firebase_util import generate_random_id
from rsa_util import RSA_Util
from tests.firebase_util_for_tests import FirebaseUtilForTests

RSA_PRIV_KEY_STR = '''-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxLHVaTHF5D1Jm/+5n+YH/Ci0QLAg/2nmyyW+QwNHZYNWc93r
QSRumjgv4Imi1kUGtpqu7PsmStGtFWlXUsaBHIgWEhBkXY1tyHv4l3r0NpFWephU
ER+ED8Uo90+sjrF4VycZAh7AS7SuMRTSJh7przV7N3Htl4GHfGUD3Kdii90uYIKP
Sq2nFOWoBzcSK6QmtnkQb3yw4zb6cVUjoBD7qPYezx9VKY/gYy7qGNq9vooKXOdH
se7oLCZ+5O0QbeaPY53aLuJbs2KJtTr0iwEmyA2ELJKs3fQiVEKeitbAybOk/2mv
gCXQcQLrN1H2rl/cpEYN6f6qJxjgPTktt+dnkQIDAQABAoIBAHEaZUIxGb7tswce
HGoixxKrgUL1RHQ6PDkygd5c41AvHqZPxLhXr7XEe1tdKaKWXI7iEZY5sMIzIZj/
UvRJKvLyGebXQC8/ZRJ0nvTUAdvi5Nxn/Wc/PRwoXi8fxHTk/fL3i3zZm++sfMHC
XDkJa4yRb0HppBqLpBHWsErQgW00hlVjM6Wlrs1pvWFPACJ5/GO65f2JJ+UtbKsS
IPeb6DN1SssE7kdSI7RVUCQTfEwRtTKXmHYtlE6/Z/EPJKE7pPwBfTHYEtcs+SOW
HAz5fntX5IE4A2NLTu4P+dRCUqjF46zmSJd4/3pPT0MkfOJyjDWRP/TxNE+Jxq3U
XdpbPkECgYEA8vNuNP6/oNceASk5gyGWADdsoCHZ3ODLqh4Wm9Jk74uOZEEKd6tY
23hAY9AGDTgrEj8mh5uVMDJvGfQ2GVsLDU8dCIZUmMciRBwIiOlexvWnyRGqW3o8
E9qCBChPwp2kT1Qttilaxhvroi5xzPB+d50TIK8o6XpypGbGSRFMpvkCgYEAz0Jh
glYjPSgSc+Cd6HtDKkE8WI0r4keT/7+Kxs4NpxPrKTTh6h6ql0lc/dkgcbtkOazH
A2U5ufTzFMAwzW3X1OCe5BKILDxE1bDlhj8TU+hkHXnb0jn06/NE2JvK5dTi7LyJ
ZiWJ6+kaBOA6I2CBb9eP7Z2gcDDdKWWe+eGb81kCgYBtm3OqBxBvQP3xaibfSUTC
Pj8Mk5kVtHlN+5sZm7cb92s7Qbi2OqCxCzSJk21Xg3KzHbiFT6TkBKzpGatajx+S
VpHzqZ76+kQ0VC1pj1fKDUQwS37/HEuEbX1g4MrzM2nQvFqPJ2Mjo68QEUIYQpvb
3QqnIT8k7rBQCWoFxv89CQKBgQCQ44/1JLB31Wao+VKKrnjyti4wnWgbRPyyoj2q
42tp7KPN57kzCQMqxc+rajmjKGRVaXKq7f3gANxaGk1Dn1Ft8SVCva3SdsOMO6EJ
K1kgpGowrPq+SWPt+t+bKbY624tUAi1vajiz4f4dgH9EMffqruBgNXxuUcqaYP81
IsH56QKBgHJMqUAcAxrzTMOXkcWD0nySn8RIysDEK1uhTI2OdtmI5/HDo1cn6M1F
wrwcScYdf7NrZoVuncVT+SbZAWPo8MM8cF9IS7RBfanEGdL7ZEsPRUtJ5aQqKJdd
MfmAKSUHB7O9aWbdBsjO5b3tXHbk6p7J9nSEsXQ7Pn8KXqpVotuK
-----END RSA PRIVATE KEY-----'''

ONE_HOUR_IN_SEC = 60 * 60

TEST_USER_UID = "abcde1234"


def _get_test_user_id_token():
    return _get_user_id_token(TEST_USER_UID)


def _get_user_id_token(uid):
    custom_token = auth.create_custom_token(uid)
    body = {'token': custom_token.decode(), 'returnSecureToken': True}
    params = {'key': 'AIzaSyBokA5Dk9M_1uz8GNeVSz4tKxmvbYRr6O4'}
    resp = requests.request('post', 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken',
                            params=params, json=body)
    resp.raise_for_status()
    return resp.json().get('idToken')


class AppTestCase(unittest.TestCase):
    fb_util = FirebaseUtilForTests()
    create_fb_util(fb_util)
    client = app.test_client()
    rsa = RSA_Util(key_str=RSA_PRIV_KEY_STR)

    test_user_id_token = _get_test_user_id_token()

    def setUp(self):
        self.fb_util.delete_key("")

        # create 2 doors:
        self.door1 = {
            'MAC': 'AA:00:AA:00:AA:00',
            'BLE': 'AA:00:AA:00:AA:01',
            'IP': '127.0.0.1',
            'certificate': 'MIIDnDCCAoQCFCgMck/fiKWOmeNKNcQTKI66xXUEMA0GCSqGSIb3DQEBCwUAMIGqMQswCQYDVQQGEwJQVDEPMA0GA1UECAwGTGlzYm9uMQ8wDQYDVQQHDAZMaXNib24xHTAbBgNVBAoMFE1TYyBCZXJuYXJkbyBNYXJxdWVzMQswCQYDVQQLDAJDQTEZMBcGA1UEAwwQQmVybmFyZG8gTWFycXVlczEyMDAGCSqGSIb3DQEJARYjYmVybmFyZG9jbWFycXVlc0B0ZWNuaWNvLnVsaXNib2EucHQwHhcNMjIwNDI1MTQ1ODU1WhcNMjMwNDI1MTQ1ODU1WjBqMQswCQYDVQQGEwJQVDEPMA0GA1UECAwGTGlzYm9uMQ8wDQYDVQQHDAZMaXNib24xHTAbBgNVBAoMFE1TYyBCZXJuYXJkbyBNYXJxdWVzMRowGAYDVQQDDBE3QzpERjpBMToxQTowRTo1QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMSx1WkxxeQ9SZv/uZ/mB/wotECwIP9p5sslvkMDR2WDVnPd60Ekbpo4L+CJotZFBraaruz7JkrRrRVpV1LGgRyIFhIQZF2Nbch7+Jd69DaRVnqYVBEfhA/FKPdPrI6xeFcnGQIewEu0rjEU0iYe6a81ezdx7ZeBh3xlA9ynYovdLmCCj0qtpxTlqAc3EiukJrZ5EG98sOM2+nFVI6AQ+6j2Hs8fVSmP4GMu6hjavb6KClznR7Hu6CwmfuTtEG3mj2Od2i7iW7NiibU69IsBJsgNhCySrN30IlRCnorWwMmzpP9pr4Al0HEC6zdR9q5f3KRGDen+qicY4D05LbfnZ5ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAVIZYs/w7f+m8df7ceUFkR6mfWZDMr+NrBwsKfoM3ezlgQUcmcezYuRadvn94KxDw2QL65d0vQvTCVFSXOnbb1wQktXrRtueo9Dat+rwMccOORq2lMO1B/zrhjXSNVh4Aou2fzvNJXC5yC3sAnKfBMDEhxvsct+jT+MogCXKh7r8gRHErY2FoEDge9RvkWDZFqIOeLt8/juALdOjsU+XDaKK6oAb+N4pVun7KxiXFussoX/3bf3y6kVLwUmvse9OhmXt4R7jV1jn6kFUpYetqhrAQcvP5Id3fc3op+su0j51RgHZ5n2tKirR9TgauTvo8Ag5JM5mL3bllWdI2wnSmlA=='
        }

        self.door2 = {
            'MAC': 'BB:00:BB:00:BB:00',
            'BLE': 'BB:00:BB:00:BB:01',
            'IP': '127.0.0.1',
            'certificate': 'MIIDnDCCAoQCFCgMck/fiKWOmeNKNcQTKI66xXUEMA0GCSqGSIb3DQEBCwUAMIGqMQswCQYDVQQGEwJQVDEPMA0GA1UECAwGTGlzYm9uMQ8wDQYDVQQHDAZMaXNib24xHTAbBgNVBAoMFE1TYyBCZXJuYXJkbyBNYXJxdWVzMQswCQYDVQQLDAJDQTEZMBcGA1UEAwwQQmVybmFyZG8gTWFycXVlczEyMDAGCSqGSIb3DQEJARYjYmVybmFyZG9jbWFycXVlc0B0ZWNuaWNvLnVsaXNib2EucHQwHhcNMjIwNDI1MTQ1ODU1WhcNMjMwNDI1MTQ1ODU1WjBqMQswCQYDVQQGEwJQVDEPMA0GA1UECAwGTGlzYm9uMQ8wDQYDVQQHDAZMaXNib24xHTAbBgNVBAoMFE1TYyBCZXJuYXJkbyBNYXJxdWVzMRowGAYDVQQDDBE3QzpERjpBMToxQTowRTo1QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMSx1WkxxeQ9SZv/uZ/mB/wotECwIP9p5sslvkMDR2WDVnPd60Ekbpo4L+CJotZFBraaruz7JkrRrRVpV1LGgRyIFhIQZF2Nbch7+Jd69DaRVnqYVBEfhA/FKPdPrI6xeFcnGQIewEu0rjEU0iYe6a81ezdx7ZeBh3xlA9ynYovdLmCCj0qtpxTlqAc3EiukJrZ5EG98sOM2+nFVI6AQ+6j2Hs8fVSmP4GMu6hjavb6KClznR7Hu6CwmfuTtEG3mj2Od2i7iW7NiibU69IsBJsgNhCySrN30IlRCnorWwMmzpP9pr4Al0HEC6zdR9q5f3KRGDen+qicY4D05LbfnZ5ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAVIZYs/w7f+m8df7ceUFkR6mfWZDMr+NrBwsKfoM3ezlgQUcmcezYuRadvn94KxDw2QL65d0vQvTCVFSXOnbb1wQktXrRtueo9Dat+rwMccOORq2lMO1B/zrhjXSNVh4Aou2fzvNJXC5yC3sAnKfBMDEhxvsct+jT+MogCXKh7r8gRHErY2FoEDge9RvkWDZFqIOeLt8/juALdOjsU+XDaKK6oAb+N4pVun7KxiXFussoX/3bf3y6kVLwUmvse9OhmXt4R7jV1jn6kFUpYetqhrAQcvP5Id3fc3op+su0j51RgHZ5n2tKirR9TgauTvo8Ag5JM5mL3bllWdI2wnSmlA=='
        }

    def test_ping(self):
        expected_response = {'success': True}
        response = self.client.get("/")

        self.assertEqual(200, response.status_code)
        self.assertEqual(expected_response, response.json)

    def test_get_all_icons(self):
        expected_response = {
            'icons': ['bed', 'briefcase', 'building', 'car-rear', 'car-side', 'car', 'caravan', 'computer', 'couch',
                      'door-closed', 'door-open', 'hotel', 'house-chimney-user', 'house-chimney', 'house',
                      'kitchen-set', 'lock-open', 'lock', 'mug-hot', 'shop', 'square-parking'],
            'success': True
        }
        response = self.client.get("/get-all-icons")

        self.assertEqual(200, response.status_code)
        self.assertEqual(expected_response, response.json)

    def test_get_icon_ok(self):
        expected_response_mimetype = "image/png"

        icon_id = "briefcase"
        response = self.client.get(f"/get-icon?icon_id={icon_id}")

        self.assertEqual(200, response.status_code)
        self.assertEqual(expected_response_mimetype, response.mimetype)

    def test_get_icon_invalid_icon_id(self):
        icon_id = "invalid"
        expected_response = f"Icon with ID \"{icon_id}\" does no exist"
        response = self.client.get(f"/get-icon?icon_id={icon_id}")

        self.assertEqual(404, response.status_code)
        self.assertEqual(expected_response, response.text)

    def test_get_icon_no_icon_id(self):
        expected_response = f"icon_id not provided"
        response = self.client.get(f"/get-icon")

        self.assertEqual(404, response.status_code)
        self.assertEqual(expected_response, response.text)

    def test_register_phone_id_ok(self):
        id_token = self.test_user_id_token
        phone_id = generate_random_id(15)

        post_data = {
            'id_token': id_token,
            'phone_id': phone_id
        }

        response = self.client.post(f"/register-phone-id", json=post_data)

        self.assertEqual(200, response.status_code)
        self.assertEqual({'success': True}, response.json)
        self.fb_util.delete_key(f'users/{TEST_USER_UID}')

    def test_register_phone_id_no_id_token(self):
        phone_id = generate_random_id(15)

        post_data = {
            'phone_id': phone_id
        }

        response = self.client.post(f"/register-phone-id", json=post_data)

        self.assertEqual(200, response.status_code)
        self.assertEqual({'success': False, 'code': 403, 'msg': 'No Id Token'}, response.json)

    def test_register_phone_id_invalid_id_token(self):
        id_token = "INVALID ID TOKEN"
        phone_id = generate_random_id(15)

        post_data = {
            'id_token': id_token,
            'phone_id': phone_id
        }

        response = self.client.post(f"/register-phone-id", json=post_data)

        self.assertEqual(200, response.status_code)
        self.assertEqual({'success': False, 'code': 403, 'msg': 'Invalid Id Token'}, response.json)

    def test_register_phone_id_no_phone_id(self):
        id_token = self.test_user_id_token

        post_data = {
            'id_token': id_token,
        }

        response = self.client.post(f"/register-phone-id", json=post_data)

        self.assertEqual(200, response.status_code)
        self.assertEqual({'success': False, 'code': 403, 'msg': 'No Phone Id'}, response.json)

    def test_register_door_lock_ok(self):
        expected_response = {'success': True}

        post_data = {
            'MAC': self.door1['MAC'],
            'BLE': self.door1['BLE'],
            'certificate': self.door1['certificate']
        }

        response = self.client.post(f"/register-door-lock", json=post_data)

        self.assertEqual(200, response.status_code)
        self.assertEqual(expected_response, response.json)
        self.assertEqual(self.door1, self.fb_util.get_data(f'doors/{self.door1["MAC"]}'))
        self.fb_util.delete_key(f'doors/{self.door1["MAC"]}')

    def test_register_door_lock_invalid_post_data(self):
        expected_response = {'success': False, 'code': 400, 'msg': 'Missing arguments.'}

        post_data = {
            'MAC': self.door1['MAC'],
            'certificate': self.door1['certificate']
        }

        response = self.client.post(f"/register-door-lock", json=post_data)

        self.assertEqual(200, response.status_code)
        self.assertEqual(expected_response, response.json)
        self.assertEqual(None, self.fb_util.get_data(f'doors/{self.door1["MAC"]}'))

    def test_door_get_certificate_ok(self):
        self.fb_util.set_data(f'doors/{self.door1["MAC"]}', self.door1)

        expected_response = {'success': True, 'certificate': self.door1['certificate']}

        id_token = self.test_user_id_token

        response = self.client.get(f"/get-door-certificate?id_token={id_token}&smart_lock_mac={self.door1['MAC']}")

        self.assertEqual(200, response.status_code)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'doors/{self.door1["MAC"]}')

    def test_door_get_certificate_invalid_id_token(self):
        self.fb_util.set_data(f'doors/{self.door1["MAC"]}', self.door1)

        expected_response = {'success': False, 'code': 403, 'msg': 'Invalid Id Token'}

        id_token = "INVALID_TOKEN"

        response = self.client.get(f"/get-door-certificate?id_token={id_token}&smart_lock_mac={self.door1['MAC']}")

        self.assertEqual(200, response.status_code)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'doors/{self.door1["MAC"]}')

    def test_door_get_certificate_no_id_token(self):
        self.fb_util.set_data(f'doors/{self.door1["MAC"]}', self.door1)

        expected_response = {'success': False, 'code': 403, 'msg': 'No Id Token'}

        response = self.client.get(f"/get-door-certificate?smart_lock_mac={self.door1['MAC']}")

        self.assertEqual(200, response.status_code)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'doors/{self.door1["MAC"]}')

    def test_door_get_certificate_no_smart_lock_mac(self):
        self.fb_util.set_data(f'doors/{self.door1["MAC"]}', self.door1)

        expected_response = {'success': False, 'code': 400, 'msg': 'No smart_lock_mac'}

        id_token = self.test_user_id_token

        response = self.client.get(f"/get-door-certificate?id_token={id_token}")

        self.assertEqual(200, response.status_code)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'doors/{self.door1["MAC"]}')

    def test_door_get_certificate_invalid_smart_lock_mac(self):
        self.fb_util.set_data(f'doors/{self.door1["MAC"]}', self.door1)

        expected_response = {'success': False, 'code': 400, 'msg': 'Invalid smart_lock_mac'}

        id_token = self.test_user_id_token

        response = self.client.get(f"/get-door-certificate?id_token={id_token}&smart_lock_mac={self.door2['MAC']}")

        self.assertEqual(200, response.status_code)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'doors/{self.door1["MAC"]}')

    def _register_invite_ok_aux(self, invite):
        invite_str = json.dumps(invite)

        signature = self.rsa.sign(invite_str)

        post_data = {
            'signature': signature.decode(),
            'data': invite_str
        }

        response = self.client.post(f"/register-invite", json=post_data)

        invite_id = base64.b64decode(response.json['inviteID']).decode().split(" ")[0]
        self.assertTrue(response.json['success'])

        if invite.get("weekdays_str"):
            invite["weekdays"] = [int(i) for i in invite["weekdays_str"]]
            del invite["weekdays_str"]
        self.assertEqual(invite, self.fb_util.get_data(f"invites/{invite_id}"))
        self.fb_util.delete_key(f"invites/{invite_id}")

    def test_register_invite_ok_admin(self):
        self.fb_util.set_data(f"doors/{self.door1['MAC']}", self.door1)
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC
        }
        self._register_invite_ok_aux(invite)
        self.fb_util.delete_key(f"doors/{self.door1['MAC']}")

    def test_register_invite_ok_owner(self):
        self.fb_util.set_data(f"doors/{self.door1['MAC']}", self.door1)
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 1,  # owner
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC
        }
        self._register_invite_ok_aux(invite)
        self.fb_util.delete_key(f"doors/{self.door1['MAC']}")

    def test_register_invite_ok_tenant(self):
        self.fb_util.set_data(f"doors/{self.door1['MAC']}", self.door1)
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 2,  # tenant
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'valid_from': int(time.time()),
            'valid_until': int(time.time()) + 30 * 24 + ONE_HOUR_IN_SEC
        }

        self._register_invite_ok_aux(invite)
        self.fb_util.delete_key(f"doors/{self.door1['MAC']}")

    def test_register_invite_ok_periodic_user(self):
        self.fb_util.set_data(f"doors/{self.door1['MAC']}", self.door1)
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 3,  # periodic_user
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'weekdays_str': "234",
            'valid_from': int(time.time()),
            'valid_until': int(time.time()) + 30 * 24 + ONE_HOUR_IN_SEC
        }

        self._register_invite_ok_aux(invite)
        self.fb_util.delete_key(f"doors/{self.door1['MAC']}")

    def test_register_invite_ok_one_time_user(self):
        self.fb_util.set_data(f"doors/{self.door1['MAC']}", self.door1)
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 4,  # one_time_user
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'one_day': int(time.time()) + 24 * ONE_HOUR_IN_SEC,
        }

        self._register_invite_ok_aux(invite)
        self.fb_util.delete_key(f"doors/{self.door1['MAC']}")

    def test_register_invite_not_signed(self):
        self.fb_util.set_data(f"doors/{self.door1['MAC']}", self.door1)
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC
        }

        invite_str = json.dumps(invite)

        post_data = {
            'data': invite_str
        }

        response = self.client.post(f"/register-invite", json=post_data)

        self.assertEqual({'success': False, 'code': 403, 'msg': 'Message not signed'}, response.json)
        self.fb_util.delete_key(f"doors/{self.door1['MAC']}")

    def test_register_invite_no_data(self):
        self.fb_util.set_data(f"doors/{self.door1['MAC']}", self.door1)
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC
        }

        invite_str = json.dumps(invite)

        signature = self.rsa.sign(invite_str)

        post_data = {
            'signature': signature.decode(),
        }

        response = self.client.post(f"/register-invite", json=post_data)

        self.assertEqual({'success': False, 'code': 400, 'msg': 'Invalid data'}, response.json)
        self.fb_util.delete_key(f"doors/{self.door1['MAC']}")

    def test_register_invite_invalid_signature(self):
        self.fb_util.set_data(f"doors/{self.door1['MAC']}", self.door1)
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC
        }

        invite_str = json.dumps(invite)

        signature = b"INVALID SIGNATURE"

        post_data = {
            'data': invite_str,
            'signature': signature.decode(),
        }

        response = self.client.post(f"/register-invite", json=post_data)

        self.assertEqual({'success': False, 'code': 403, 'msg': 'Invalid signature'}, response.json)
        self.fb_util.delete_key(f"doors/{self.door1['MAC']}")

    def _aux_test_redeem_invite(self,
                                expected_response,
                                invite=None,
                                phone_id=generate_random_id(15),
                                master_key="Xe3XKOcYrVHa4sUokx8lhrDDG2b1sgx1qc6F9++8R08=",
                                id_token=_get_test_user_id_token(),
                                redeem_invite_id=None,
                                redeem_phone_id=None):
        post_data = {}
        invite_id = None
        if invite:
            invite_id = generate_random_id(32)
            if not redeem_invite_id:
                redeem_invite_id = invite_id
            self.fb_util.set_data(f'invites/{invite_id}', invite)
            post_data['invite_id'] = redeem_invite_id

        if phone_id:
            if not redeem_phone_id:
                redeem_phone_id = phone_id
            self.fb_util.set_data(f'users/{TEST_USER_UID}', {'phone_ids': [phone_id]})
            post_data['phone_id'] = redeem_phone_id

        if master_key:
            master_key_lock = master_key
            master_key_encrypted_lock = self.rsa.encrypt_msg(master_key_lock)
            post_data['master_key_encrypted_lock'] = master_key_encrypted_lock.decode()

        if id_token:
            post_data['id_token'] = id_token

        response = self.client.post("/redeem-invite", json=post_data)
        self.assertEqual(expected_response, response.json)

        if response.json['success']:
            authorization = {
                'master_key_encrypted_lock': post_data['master_key_encrypted_lock'],
                'phone_id': post_data['phone_id'],
                'smart_lock_MAC': invite['smart_lock_MAC'],
                'type': invite['type'],

            }

            if invite["type"] == 2 or invite["type"] == 3:
                authorization["valid_from"] = invite["valid_from"]
                authorization["valid_until"] = invite["valid_until"]

            if invite["type"] == 3:
                authorization["weekdays"] = invite["weekdays"]

            if invite["type"] == 4:
                authorization["one_day"] = invite["one_day"]

            self.assertEqual(authorization,
                             self.fb_util.get_data(f'authorizations/{invite["smart_lock_MAC"]}/{phone_id}'))
            self.fb_util.delete_key(f'authorizations/{invite["smart_lock_MAC"]}/{phone_id}')

        if invite:
            self.fb_util.delete_key(f'invites/{invite_id}')

        if phone_id:
            self.fb_util.delete_key(f'users/{TEST_USER_UID}')

    def test_redeem_invite_ok_admin(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC
        }

        self._aux_test_redeem_invite(
            expected_response={'success': True},
            invite=invite)

    def test_redeem_invite_ok_owner(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 1,  # owner
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC
        }

        self._aux_test_redeem_invite(
            expected_response={'success': True},
            invite=invite)

    def test_redeem_invite_ok_tenant(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 2,  # tenant
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'valid_from': int(time.time()),
            'valid_until': int(time.time()) + 30 * 24 + ONE_HOUR_IN_SEC
        }

        self._aux_test_redeem_invite(
            expected_response={'success': True},
            invite=invite)

    def test_redeem_invite_ok_periodic_user(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 3,  # periodic_user
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'weekdays': [2, 3, 5],
            'valid_from': int(time.time()),
            'valid_until': int(time.time()) + 30 * 24 + ONE_HOUR_IN_SEC
        }

        self._aux_test_redeem_invite(
            expected_response={'success': True},
            invite=invite)

    def test_redeem_invite_ok_one_time_user(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 4,  # one_time_user
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'one_day': int(time.time()) + 24 * ONE_HOUR_IN_SEC,
        }

        self._aux_test_redeem_invite(
            expected_response={'success': True},
            invite=invite)

    def test_redeem_invite_no_id_token(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC
        }

        self._aux_test_redeem_invite(
            expected_response={'code': 403, 'msg': 'No Id Token', 'success': False},
            invite=invite,
            id_token=None
        )

    def test_redeem_invite_invalid_id_token(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC
        }

        self._aux_test_redeem_invite(
            expected_response={'success': False, 'code': 403, 'msg': 'Invalid Id Token'},
            invite=invite,
            id_token="INVALID_ID_TOKEN")

    def test_redeem_invite_no_invite_id(self):
        self._aux_test_redeem_invite(
            expected_response={'success': False, 'code': 400, 'msg': 'No invite id'}
        )

    def test_redeem_invite_invalid_invite_id(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC
        }

        self._aux_test_redeem_invite(
            expected_response={'success': False, 'code': 400, 'msg': 'Invalid invite'},
            invite=invite,
            redeem_invite_id="INVALID_INVITE_ID"
        )

    def test_redeem_invite_invalid_phone_id(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
        }

        self._aux_test_redeem_invite(
            expected_response={'success': False, 'code': 403, 'msg': 'Invalid Phone Id!'},
            invite=invite,
            redeem_phone_id="INVALID_PHONE_ID"
        )

    def test_redeem_invite_email_locked_ok(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "python_test_user@test.com"
        }

        self._aux_test_redeem_invite(
            expected_response={'success': True},
            invite=invite
        )

    def test_redeem_invite_email_locked_not_ok(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "not_python_test_user@test.com"
        }

        self._aux_test_redeem_invite(
            expected_response={'success': False, 'code': 403, 'msg': 'No permissions. This invite is user locked!'},
            invite=invite,
        )

    def test_save_user_invite_ok(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)

        post_data = {
            'id_token': self.test_user_id_token,
            'lock_id': self.door1['MAC'],
            'invite_id': invite_id
        }

        expected_response = {'success': True}
        response = self.client.post("/save-user-invite", json=post_data)
        self.assertEqual(expected_response, response.json)
        self.assertEqual(invite_id,
                         self.fb_util.get_data(f'users/{TEST_USER_UID}/locks/{self.door1["MAC"]}/saved_invite'))
        self.fb_util.delete_key(f'invites/{invite_id}')
        self.fb_util.delete_key(f'users/{TEST_USER_UID}/locks/{self.door1["MAC"]}/saved_invite')

    def test_save_user_invite_no_id_token(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)

        post_data = {
            'lock_id': self.door1['MAC'],
            'invite_id': invite_id
        }

        expected_response = {'success': False, 'code': 403, 'msg': 'No Id Token'}
        response = self.client.post("/save-user-invite", json=post_data)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'invites/{invite_id}')

    def test_save_user_invite_invalid_id_token(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)

        post_data = {
            'id_token': "INVALID ID TOKEN",
            'lock_id': self.door1['MAC'],
            'invite_id': invite_id
        }

        expected_response = {'success': False, 'code': 403, 'msg': 'Invalid Id Token'}
        response = self.client.post("/save-user-invite", json=post_data)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'invites/{invite_id}')

    def test_save_user_invite_no_invite_id(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)

        post_data = {
            'id_token': self.test_user_id_token,
            'lock_id': self.door1['MAC']
        }

        expected_response = {'success': False, 'code': 400, 'msg': 'No invite id'}
        response = self.client.post("/save-user-invite", json=post_data)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'invites/{invite_id}')

    def test_save_user_invite_no_id_lock(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)

        post_data = {
            'id_token': self.test_user_id_token,
            'invite_id': invite_id
        }

        expected_response = {'success': False, 'code': 400, 'msg': 'No lock id'}
        response = self.client.post("/save-user-invite", json=post_data)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'invites/{invite_id}')

    def test_save_user_invite_invalid_invite_id(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)

        post_data = {
            'id_token': self.test_user_id_token,
            'lock_id': self.door1['MAC'],
            'invite_id': "INVALID_INVITE_ID"
        }

        expected_response = {'success': False, 'code': 400, 'msg': 'Invalid invite'}
        response = self.client.post("/save-user-invite", json=post_data)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'invites/{invite_id}')

    def test_save_user_invite_locked_wrong_user(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "not_python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)

        post_data = {
            'id_token': self.test_user_id_token,
            'lock_id': self.door1['MAC'],
            'invite_id': invite_id
        }

        expected_response = {'success': False, 'code': 403, 'msg': 'No permissions. This invite is user locked!'}
        response = self.client.post("/save-user-invite", json=post_data)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'invites/{invite_id}')

    def test_check_user_invite_ok_got_invite(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)
        self.fb_util.set_data(f'users/{TEST_USER_UID}/locks/{self.door1["MAC"]}', {'saved_invite': invite_id})

        expected_response = {'success': True, "got_invite": True}
        response = self.client.get(f"/check-user-invite?id_token={self.test_user_id_token}&lock_id={self.door1['MAC']}")
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'invites/{invite_id}')
        self.fb_util.delete_key(f'users/{TEST_USER_UID}/locks/{self.door1["MAC"]}/saved_invite')

    def test_check_user_invite_ok_not_got_invite(self):
        expected_response = {'success': True, "got_invite": False}
        response = self.client.get(f"/check-user-invite?id_token={self.test_user_id_token}&lock_id={self.door1['MAC']}")
        self.assertEqual(expected_response, response.json)

    def test_check_user_invite_no_id_token(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)
        self.fb_util.set_data(f'users/{TEST_USER_UID}/locks/{self.door1["MAC"]}', {'saved_invite': invite_id})

        expected_response = {'success': False, 'code': 403, 'msg': 'No Id Token'}
        response = self.client.get(f"/check-user-invite?lock_id={self.door1['MAC']}")
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'invites/{invite_id}')
        self.fb_util.delete_key(f'users/{TEST_USER_UID}/locks/{self.door1["MAC"]}/saved_invite')

    def test_check_user_invite_invalid_id_token(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)
        self.fb_util.set_data(f'users/{TEST_USER_UID}/locks/{self.door1["MAC"]}', {'saved_invite': invite_id})

        expected_response = {'success': False, 'code': 403, 'msg': 'Invalid Id Token'}
        response = self.client.get(f"/check-user-invite?id_token=INVALID_ID_TOKEN&lock_id={self.door1['MAC']}")
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'invites/{invite_id}')
        self.fb_util.delete_key(f'users/{TEST_USER_UID}/locks/{self.door1["MAC"]}/saved_invite')

    def test_check_user_invite_no_lock_id(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)
        self.fb_util.set_data(f'users/{TEST_USER_UID}/locks/{self.door1["MAC"]}', {'saved_invite': invite_id})

        expected_response = {'success': False, 'code': 400, 'msg': 'No lock id'}
        response = self.client.get(f"/check-user-invite?id_token={self.test_user_id_token}")
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'invites/{invite_id}')
        self.fb_util.delete_key(f'users/{TEST_USER_UID}/locks/{self.door1["MAC"]}/saved_invite')

    def test_redeem_user_invite_ok(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)
        self.fb_util.set_data(f'users/{TEST_USER_UID}/locks/{self.door1["MAC"]}', {'saved_invite': invite_id})

        master_key_lock = "Xe3XKOcYrVHa4sUokx8lhrDDG2b1sgx1qc6F9++8R08="
        master_key_encrypted_lock = self.rsa.encrypt_msg(master_key_lock)

        phone_id = generate_random_id(15)
        self.fb_util.set_data(f'users/{TEST_USER_UID}', {'phone_ids': [phone_id]})

        post_data = {
            'id_token': self.test_user_id_token,
            'phone_id': phone_id,
            'lock_id': self.door1['MAC'],
            'master_key_encrypted_lock': master_key_encrypted_lock.decode()
        }

        expected_response = {'success': True}
        response = self.client.post("/redeem-user-invite", json=post_data)
        self.assertEqual(expected_response, response.json)
        authorization = {
            'master_key_encrypted_lock': post_data['master_key_encrypted_lock'],
            'phone_id': post_data['phone_id'],
            'smart_lock_MAC': invite['smart_lock_MAC'],
            'type': invite['type'],

        }

        if invite["type"] == 2 or invite["type"] == 3:
            authorization["valid_from"] = invite["valid_from"]
            authorization["valid_until"] = invite["valid_until"]

        if invite["type"] == 3:
            authorization["weekdays"] = invite["weekdays"]

        if invite["type"] == 4:
            authorization["one_day"] = invite["one_day"]

        self.assertEqual(authorization,
                         self.fb_util.get_data(f'authorizations/{invite["smart_lock_MAC"]}/{phone_id}'))

        self.fb_util.delete_key("/")

    def test_redeem_user_invite_no_token_id(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)
        self.fb_util.set_data(f'users/{TEST_USER_UID}/locks/{self.door1["MAC"]}', {'saved_invite': invite_id})

        master_key_lock = "Xe3XKOcYrVHa4sUokx8lhrDDG2b1sgx1qc6F9++8R08="
        master_key_encrypted_lock = self.rsa.encrypt_msg(master_key_lock)

        phone_id = generate_random_id(15)
        self.fb_util.set_data(f'users/{TEST_USER_UID}', {'phone_ids': [phone_id]})

        post_data = {
            'phone_id': phone_id,
            'lock_id': self.door1['MAC'],
            'master_key_encrypted_lock': master_key_encrypted_lock.decode()
        }

        expected_response = {'success': False, 'code': 403, 'msg': 'No Id Token'}
        response = self.client.post("/redeem-user-invite", json=post_data)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key("/")

    def test_redeem_user_invite_no_phone_id(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)
        self.fb_util.set_data(f'users/{TEST_USER_UID}/locks/{self.door1["MAC"]}', {'saved_invite': invite_id})

        master_key_lock = "Xe3XKOcYrVHa4sUokx8lhrDDG2b1sgx1qc6F9++8R08="
        master_key_encrypted_lock = self.rsa.encrypt_msg(master_key_lock)

        phone_id = generate_random_id(15)
        self.fb_util.set_data(f'users/{TEST_USER_UID}', {'phone_ids': [phone_id]})

        post_data = {
            'id_token': self.test_user_id_token,
            'lock_id': self.door1['MAC'],
            'master_key_encrypted_lock': master_key_encrypted_lock.decode()
        }

        expected_response = {'success': False, 'code': 403, 'msg': 'No Phone Id'}
        response = self.client.post("/redeem-user-invite", json=post_data)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key("/")

    def test_redeem_user_invite_no_lock_id(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)
        self.fb_util.set_data(f'users/{TEST_USER_UID}/locks/{self.door1["MAC"]}', {'saved_invite': invite_id})

        master_key_lock = "Xe3XKOcYrVHa4sUokx8lhrDDG2b1sgx1qc6F9++8R08="
        master_key_encrypted_lock = self.rsa.encrypt_msg(master_key_lock)

        phone_id = generate_random_id(15)
        self.fb_util.set_data(f'users/{TEST_USER_UID}', {'phone_ids': [phone_id]})

        post_data = {
            'id_token': self.test_user_id_token,
            'phone_id': phone_id,
            'master_key_encrypted_lock': master_key_encrypted_lock.decode()
        }

        expected_response = {'success': False, 'code': 400, 'msg': 'No lock id'}
        response = self.client.post("/redeem-user-invite", json=post_data)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key("/")

    def test_redeem_user_invite_no_master_key(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)
        self.fb_util.set_data(f'users/{TEST_USER_UID}/locks/{self.door1["MAC"]}', {'saved_invite': invite_id})

        phone_id = generate_random_id(15)
        self.fb_util.set_data(f'users/{TEST_USER_UID}', {'phone_ids': [phone_id]})

        post_data = {
            'id_token': self.test_user_id_token,
            'phone_id': phone_id,
            'lock_id': self.door1['MAC']
        }

        expected_response = {'success': False, 'code': 403, 'msg': 'No Master Key'}
        response = self.client.post("/redeem-user-invite", json=post_data)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key("/")

    def test_redeem_user_invite_invalid_id_token(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)
        self.fb_util.set_data(f'users/{TEST_USER_UID}/locks/{self.door1["MAC"]}', {'saved_invite': invite_id})

        master_key_lock = "Xe3XKOcYrVHa4sUokx8lhrDDG2b1sgx1qc6F9++8R08="
        master_key_encrypted_lock = self.rsa.encrypt_msg(master_key_lock)

        phone_id = generate_random_id(15)
        self.fb_util.set_data(f'users/{TEST_USER_UID}', {'phone_ids': [phone_id]})

        post_data = {
            'id_token': "INVALID_ID_TOKEN",
            'phone_id': phone_id,
            'lock_id': self.door1['MAC'],
            'master_key_encrypted_lock': master_key_encrypted_lock.decode()
        }

        expected_response = {'success': False, 'code': 403, 'msg': 'Invalid Id Token'}
        response = self.client.post("/redeem-user-invite", json=post_data)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key("/")

    def test_redeem_user_invite_invite_not_saved(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)

        master_key_lock = "Xe3XKOcYrVHa4sUokx8lhrDDG2b1sgx1qc6F9++8R08="
        master_key_encrypted_lock = self.rsa.encrypt_msg(master_key_lock)

        phone_id = generate_random_id(15)
        self.fb_util.set_data(f'users/{TEST_USER_UID}', {'phone_ids': [phone_id]})

        post_data = {
            'id_token': self.test_user_id_token,
            'phone_id': phone_id,
            'lock_id': self.door1['MAC'],
            'master_key_encrypted_lock': master_key_encrypted_lock.decode()
        }

        expected_response = {'success': False, 'code': 500, 'msg': 'Can\'t get user saved invite.'}
        response = self.client.post("/redeem-user-invite", json=post_data)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key("/")

    def test_redeem_user_invite_no_invite(self):

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'users/{TEST_USER_UID}/locks/{self.door1["MAC"]}', {'saved_invite': invite_id})

        master_key_lock = "Xe3XKOcYrVHa4sUokx8lhrDDG2b1sgx1qc6F9++8R08="
        master_key_encrypted_lock = self.rsa.encrypt_msg(master_key_lock)

        phone_id = generate_random_id(15)
        self.fb_util.set_data(f'users/{TEST_USER_UID}', {'phone_ids': [phone_id]})

        post_data = {
            'id_token': self.test_user_id_token,
            'phone_id': phone_id,
            'lock_id': self.door1['MAC'],
            'master_key_encrypted_lock': master_key_encrypted_lock.decode()
        }

        expected_response = {'success': False, 'code': 400, 'msg': 'Invalid invite'}
        response = self.client.post("/redeem-user-invite", json=post_data)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key("/")

    def test_redeem_user_invite_email_locked_wrong(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "not_python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)
        self.fb_util.set_data(f'users/{TEST_USER_UID}/locks/{self.door1["MAC"]}', {'saved_invite': invite_id})

        master_key_lock = "Xe3XKOcYrVHa4sUokx8lhrDDG2b1sgx1qc6F9++8R08="
        master_key_encrypted_lock = self.rsa.encrypt_msg(master_key_lock)

        phone_id = generate_random_id(15)
        self.fb_util.set_data(f'users/{TEST_USER_UID}', {'phone_ids': [phone_id]})

        post_data = {
            'id_token': self.test_user_id_token,
            'phone_id': phone_id,
            'lock_id': self.door1['MAC'],
            'master_key_encrypted_lock': master_key_encrypted_lock.decode()
        }

        expected_response = {'success': False, 'code': 403, 'msg': 'No permissions. This invite is user locked!'}
        response = self.client.post("/redeem-user-invite", json=post_data)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key("/")

    def test_redeem_user_invite_invalid_phone_id(self):
        invite = {
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
            'expiration': int(time.time()) + ONE_HOUR_IN_SEC,
            'email_locked': "python_test_user@test.com"
        }

        invite_id = generate_random_id(32)
        self.fb_util.set_data(f'invites/{invite_id}', invite)
        self.fb_util.set_data(f'users/{TEST_USER_UID}/locks/{self.door1["MAC"]}', {'saved_invite': invite_id})

        master_key_lock = "Xe3XKOcYrVHa4sUokx8lhrDDG2b1sgx1qc6F9++8R08="
        master_key_encrypted_lock = self.rsa.encrypt_msg(master_key_lock)

        phone_id = generate_random_id(15)
        self.fb_util.set_data(f'users/{TEST_USER_UID}', {'phone_ids': [phone_id]})

        post_data = {
            'id_token': self.test_user_id_token,
            'phone_id': "INVALID_PHONE_ID",
            'lock_id': self.door1['MAC'],
            'master_key_encrypted_lock': master_key_encrypted_lock.decode()
        }

        expected_response = {'success': False, 'code': 403, 'msg': 'Invalid Phone Id!'}
        response = self.client.post("/redeem-user-invite", json=post_data)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key("/")

    def test_request_authorization_ok(self):
        self.fb_util.set_data(f"doors/{self.door1['MAC']}", self.door1)

        master_key_lock = "Xe3XKOcYrVHa4sUokx8lhrDDG2b1sgx1qc6F9++8R08="
        master_key_encrypted_lock = self.rsa.encrypt_msg(master_key_lock).decode()

        authorization = {
            'master_key_encrypted_lock': master_key_encrypted_lock,
            'phone_id': generate_random_id(15),
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
        }

        phone_id = generate_random_id(15)
        self.fb_util.set_data(f'authorizations/{self.door1["MAC"]}/{phone_id}', authorization)

        data = {
            'smart_lock_MAC': self.door1['MAC'],
            'phone_id': phone_id
        }

        data_str = json.dumps(data)

        signature = self.rsa.sign(data_str)

        post_data = {
            'signature': signature.decode(),
            'data': data_str
        }

        expected_response = {'success': True, 'data': authorization}
        response = self.client.post('/request-authorization', json=post_data)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'authorizations/{self.door1["MAC"]}/{phone_id}')
        self.fb_util.delete_key(f"doors/{self.door1['MAC']}")

    def test_request_authorization_not_signed(self):
        self.fb_util.set_data(f"doors/{self.door1['MAC']}", self.door1)

        master_key_lock = "Xe3XKOcYrVHa4sUokx8lhrDDG2b1sgx1qc6F9++8R08="
        master_key_encrypted_lock = self.rsa.encrypt_msg(master_key_lock).decode()

        authorization = {
            'master_key_encrypted_lock': master_key_encrypted_lock,
            'phone_id': generate_random_id(15),
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
        }

        phone_id = generate_random_id(15)
        self.fb_util.set_data(f'authorizations/{self.door1["MAC"]}/{phone_id}', authorization)

        data = {
            'smart_lock_MAC': self.door1['MAC'],
            'phone_id': phone_id
        }

        data_str = json.dumps(data)

        post_data = {
            'data': data_str
        }

        expected_response = {'success': False, 'code': 403, 'msg': 'Message not signed'}
        response = self.client.post('/request-authorization', json=post_data)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'authorizations/{self.door1["MAC"]}/{phone_id}')
        self.fb_util.delete_key(f"doors/{self.door1['MAC']}")

    def test_request_authorization_no_data(self):
        self.fb_util.set_data(f"doors/{self.door1['MAC']}", self.door1)

        master_key_lock = "Xe3XKOcYrVHa4sUokx8lhrDDG2b1sgx1qc6F9++8R08="
        master_key_encrypted_lock = self.rsa.encrypt_msg(master_key_lock).decode()

        authorization = {
            'master_key_encrypted_lock': master_key_encrypted_lock,
            'phone_id': generate_random_id(15),
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
        }

        phone_id = generate_random_id(15)
        self.fb_util.set_data(f'authorizations/{self.door1["MAC"]}/{phone_id}', authorization)

        data = {
            'smart_lock_MAC': self.door1['MAC'],
            'phone_id': phone_id
        }

        data_str = json.dumps(data)

        signature = self.rsa.sign(data_str)

        post_data = {
            'signature': signature.decode(),
        }

        expected_response = {'success': False, 'code': 400, 'msg': 'Invalid data'}
        response = self.client.post('/request-authorization', json=post_data)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'authorizations/{self.door1["MAC"]}/{phone_id}')
        self.fb_util.delete_key(f"doors/{self.door1['MAC']}")

    def test_request_authorization_invalid_signature(self):
        self.fb_util.set_data(f"doors/{self.door1['MAC']}", self.door1)

        master_key_lock = "Xe3XKOcYrVHa4sUokx8lhrDDG2b1sgx1qc6F9++8R08="
        master_key_encrypted_lock = self.rsa.encrypt_msg(master_key_lock).decode()

        authorization = {
            'master_key_encrypted_lock': master_key_encrypted_lock,
            'phone_id': generate_random_id(15),
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
        }

        phone_id = generate_random_id(15)
        self.fb_util.set_data(f'authorizations/{self.door1["MAC"]}/{phone_id}', authorization)

        data = {
            'smart_lock_MAC': self.door1['MAC'],
            'phone_id': phone_id
        }

        data_str = json.dumps(data)

        post_data = {
            'signature': "INVALID_SIGNATURE",
            'data': data_str
        }

        expected_response = {'success': False, 'code': 403, 'msg': 'Invalid signature'}
        response = self.client.post('/request-authorization', json=post_data)
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'authorizations/{self.door1["MAC"]}/{phone_id}')
        self.fb_util.delete_key(f"doors/{self.door1['MAC']}")

    def test_check_lock_registration_status_ok_registered_with_auths(self):
        self.fb_util.set_data(f"doors/{self.door1['MAC']}", self.door1)

        master_key_lock = "Xe3XKOcYrVHa4sUokx8lhrDDG2b1sgx1qc6F9++8R08="
        master_key_encrypted_lock = self.rsa.encrypt_msg(master_key_lock).decode()

        authorization = {
            'master_key_encrypted_lock': master_key_encrypted_lock,
            'phone_id': generate_random_id(15),
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
        }

        phone_id = generate_random_id(15)
        self.fb_util.set_data(f'authorizations/{self.door1["MAC"]}/{phone_id}', authorization)

        expected_response = {'success': True, 'status': 2}
        response = self.client.get(f'/check-lock-registration-status?MAC={self.door1["MAC"]}')
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f'authorizations/{self.door1["MAC"]}/{phone_id}')
        self.fb_util.delete_key(f"doors/{self.door1['MAC']}")

    def test_check_lock_registration_status_ok_registered(self):
        self.fb_util.set_data(f"doors/{self.door1['MAC']}", self.door1)

        expected_response = {'success': True, 'status': 1}
        response = self.client.get(f'check-lock-registration-status?MAC={self.door1["MAC"]}')
        self.assertEqual(expected_response, response.json)
        self.fb_util.delete_key(f"doors/{self.door1['MAC']}")

    def test_check_lock_registration_status_ok_not_registered(self):
        expected_response = {'success': True, 'status': 0}
        response = self.client.get(f'check-lock-registration-status?MAC={self.door1["MAC"]}')
        self.assertEqual(expected_response, response.json)

    def test_check_lock_registration_status_no_mac(self):
        expected_response = {'success': False, 'code': 400, 'msg': 'Missing argument MAC.'}
        response = self.client.get(f'check-lock-registration-status')
        self.assertEqual(expected_response, response.json)

    def test_get_user_locks_ok_one_lock(self):
        id_token = self.test_user_id_token
        lock1 = {
            "BLE": self.door1["BLE"],
            "MAC": self.door1["MAC"],
            "icon_id": "car-side",
            "id": self.door1["MAC"],
            "location": "38.749299,-9.1377541",
            "name": "Garage",
            "proximity_lock_active": False,
            "proximity_unlock_active": False,
            "saved_invite": generate_random_id(32)
        }

        self.fb_util.set_data(f"users/{TEST_USER_UID}/locks/{lock1['id']}", lock1)

        expected_response = {'success': True, 'locks': [lock1]}
        response = self.client.get(f'/get-user-locks?id_token={id_token}')
        self.assertEqual(expected_response, response.json)

        self.fb_util.delete_key(f"users/{TEST_USER_UID}/locks/{lock1['id']}")

    def test_get_user_locks_ok_multiple_locks(self):
        id_token = self.test_user_id_token
        lock1 = {
            "BLE": self.door1["BLE"],
            "MAC": self.door1["MAC"],
            "icon_id": "car-side",
            "id": self.door1["MAC"],
            "location": "38.749299,-9.1377541",
            "name": "Garage",
            "proximity_lock_active": False,
            "proximity_unlock_active": False,
            "saved_invite": generate_random_id(32)
        }

        lock2 = {
            "BLE": self.door2["BLE"],
            "MAC": self.door2["MAC"],
            "icon_id": "frontdoor",
            "id": self.door2["MAC"],
            "location": "38.749299,-9.1377541",
            "name": "Front Door",
            "proximity_lock_active": False,
            "proximity_unlock_active": False,
            "saved_invite": generate_random_id(32)
        }

        self.fb_util.set_data(f"users/{TEST_USER_UID}/locks/{lock1['id']}", lock1)
        self.fb_util.set_data(f"users/{TEST_USER_UID}/locks/{lock2['id']}", lock2)

        expected_response = {'success': True, 'locks': [lock1, lock2]}
        response = self.client.get(f'/get-user-locks?id_token={id_token}')
        self.assertEqual(expected_response, response.json)

        self.fb_util.delete_key(f"users/{TEST_USER_UID}/locks/{lock1['id']}")
        self.fb_util.delete_key(f"users/{TEST_USER_UID}/locks/{lock2['id']}")

    def test_get_user_locks_ok_no_locks(self):
        id_token = self.test_user_id_token

        expected_response = {'success': True, 'locks': []}
        response = self.client.get(f'/get-user-locks?id_token={id_token}')
        self.assertEqual(expected_response, response.json)

    def test_get_user_locks_invalid_id_token(self):
        id_token = "INVALID_ID_TOKEN"

        expected_response = {'success': False, 'code': 403, 'msg': 'Invalid Id Token'}
        response = self.client.get(f'/get-user-locks?id_token={id_token}')
        self.assertEqual(expected_response, response.json)

    def test_get_user_locks_no_id_token(self):
        expected_response = {'success': False, 'code': 403, 'msg': 'No Id Token'}
        response = self.client.get(f'/get-user-locks')
        self.assertEqual(expected_response, response.json)

    def test_set_user_locks_ok(self):
        lock1 = {
            "BLE": self.door1["BLE"],
            "MAC": self.door1["MAC"],
            "icon_id": "car-side",
            "id": self.door1["MAC"],
            "location": "38.749299,-9.1377541",
            "name": "Garage",
            "proximity_lock_active": False,
            "proximity_unlock_active": False,
            "saved_invite": generate_random_id(32)
        }

        post_data = {
            'id_token': self.test_user_id_token,
            'lock': lock1
        }

        expected_response = {'success': True}
        response = self.client.post('/set-user-locks', json=post_data)
        self.assertEqual(expected_response, response.json)
        self.assertEqual(lock1, self.fb_util.get_data(f"users/{TEST_USER_UID}/locks/{lock1['id']}"))
        self.assertEqual({lock1['id']: lock1}, self.fb_util.get_data(f"users/{TEST_USER_UID}/locks"))

        self.fb_util.delete_key(f"users/{TEST_USER_UID}/locks/{lock1['id']}")

    def test_set_user_locks_ok_add_to_existing(self):
        lock1 = {
            "BLE": self.door1["BLE"],
            "MAC": self.door1["MAC"],
            "icon_id": "car-side",
            "id": self.door1["MAC"],
            "location": "38.749299,-9.1377541",
            "name": "Garage",
            "proximity_lock_active": False,
            "proximity_unlock_active": False,
            "saved_invite": generate_random_id(32)
        }

        lock2 = {
            "BLE": self.door2["BLE"],
            "MAC": self.door2["MAC"],
            "icon_id": "frontdoor",
            "id": self.door2["MAC"],
            "location": "38.749299,-9.1377541",
            "name": "Front Door",
            "proximity_lock_active": False,
            "proximity_unlock_active": False,
            "saved_invite": generate_random_id(32)
        }

        self.fb_util.set_data(f"users/{TEST_USER_UID}/locks/{lock1['id']}", lock1)

        post_data = {
            'id_token': self.test_user_id_token,
            'lock': lock2
        }

        expected_response = {'success': True}
        response = self.client.post('/set-user-locks', json=post_data)
        self.assertEqual(expected_response, response.json)
        self.assertEqual(lock2, self.fb_util.get_data(f"users/{TEST_USER_UID}/locks/{lock2['id']}"))
        self.assertEqual({lock1['id']: lock1, lock2['id']: lock2},
                         self.fb_util.get_data(f"users/{TEST_USER_UID}/locks"))

        self.fb_util.delete_key(f"users/{TEST_USER_UID}/locks/{lock1['id']}")
        self.fb_util.delete_key(f"users/{TEST_USER_UID}/locks/{lock2['id']}")

    def test_set_user_locks_invalid_id_token(self):
        lock1 = {
            "BLE": self.door1["BLE"],
            "MAC": self.door1["MAC"],
            "icon_id": "car-side",
            "id": self.door1["MAC"],
            "location": "38.749299,-9.1377541",
            "name": "Garage",
            "proximity_lock_active": False,
            "proximity_unlock_active": False,
            "saved_invite": generate_random_id(32)
        }

        post_data = {
            'id_token': "INVALID_ID_TOKEN",
            'lock': lock1
        }

        expected_response = {'success': False, 'code': 403, 'msg': 'Invalid Id Token'}
        response = self.client.post('/set-user-locks', json=post_data)
        self.assertEqual(expected_response, response.json)

    def test_set_user_locks_no_id_token(self):
        lock1 = {
            "BLE": self.door1["BLE"],
            "MAC": self.door1["MAC"],
            "icon_id": "car-side",
            "id": self.door1["MAC"],
            "location": "38.749299,-9.1377541",
            "name": "Garage",
            "proximity_lock_active": False,
            "proximity_unlock_active": False,
            "saved_invite": generate_random_id(32)
        }

        post_data = {
            'lock': lock1
        }

        expected_response = {'success': False, 'code': 403, 'msg': 'No Id Token'}
        response = self.client.post('/set-user-locks', json=post_data)
        self.assertEqual(expected_response, response.json)

    def test_delete_user_lock_ok(self):
        self.fb_util.set_data(f"doors/{self.door1['MAC']}", self.door1)

        master_key_lock = "Xe3XKOcYrVHa4sUokx8lhrDDG2b1sgx1qc6F9++8R08="
        master_key_encrypted_lock = self.rsa.encrypt_msg(master_key_lock).decode()

        authorization = {
            'master_key_encrypted_lock': master_key_encrypted_lock,
            'phone_id': generate_random_id(15),
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
        }

        phone_id = generate_random_id(15)
        self.fb_util.set_data(f'authorizations/{self.door1["MAC"]}/{phone_id}', authorization)

        lock1 = {
            "BLE": self.door1["BLE"],
            "MAC": self.door1["MAC"],
            "icon_id": "car-side",
            "id": self.door1["MAC"],
            "location": "38.749299,-9.1377541",
            "name": "Garage",
            "proximity_lock_active": False,
            "proximity_unlock_active": False,
            "saved_invite": generate_random_id(32)
        }

        self.fb_util.set_data(f"users/{TEST_USER_UID}/locks/{lock1['id']}", lock1)
        self.fb_util.set_data(f'users/{TEST_USER_UID}', {'phone_ids': [phone_id]})

        post_data = {
            'id_token': self.test_user_id_token,
            'lock_id': lock1['id']
        }

        expected_response = {'success': True}
        response = self.client.post('/delete-user-lock', json=post_data)
        self.assertEqual(expected_response, response.json)
        self.assertEqual(None, self.fb_util.get_data(f"users/{TEST_USER_UID}/locks/{lock1['id']}"))
        self.assertEqual(None, self.fb_util.get_data(f"users/{TEST_USER_UID}/locks"))
        self.assertEqual(None, self.fb_util.get_data(f"authorizations/{self.door1['MAC']}/{phone_id}"))

        self.fb_util.delete_key(f"users/{TEST_USER_UID}")
        self.fb_util.delete_key(f"doors/{self.door1['MAC']}")

    def test_delete_user_lock_ok_multiple_phone_id(self):
        self.fb_util.set_data(f"doors/{self.door1['MAC']}", self.door1)

        master_key_lock = "Xe3XKOcYrVHa4sUokx8lhrDDG2b1sgx1qc6F9++8R08="
        master_key_encrypted_lock = self.rsa.encrypt_msg(master_key_lock).decode()

        authorization = {
            'master_key_encrypted_lock': master_key_encrypted_lock,
            'phone_id': generate_random_id(15),
            'smart_lock_MAC': self.door1['MAC'],
            'type': 0,  # admin
        }

        phone_id1 = generate_random_id(15)
        phone_id2 = generate_random_id(15)
        self.fb_util.set_data(f'authorizations/{self.door1["MAC"]}/{phone_id1}', authorization)
        self.fb_util.set_data(f'authorizations/{self.door1["MAC"]}/{phone_id2}', authorization)

        lock1 = {
            "BLE": self.door1["BLE"],
            "MAC": self.door1["MAC"],
            "icon_id": "car-side",
            "id": self.door1["MAC"],
            "location": "38.749299,-9.1377541",
            "name": "Garage",
            "proximity_lock_active": False,
            "proximity_unlock_active": False,
            "saved_invite": generate_random_id(32)
        }

        self.fb_util.set_data(f"users/{TEST_USER_UID}/locks/{lock1['id']}", lock1)
        self.fb_util.set_data(f'users/{TEST_USER_UID}', {'phone_ids': [phone_id1, phone_id2]})

        post_data = {
            'id_token': self.test_user_id_token,
            'lock_id': lock1['id']
        }

        expected_response = {'success': True}
        response = self.client.post('/delete-user-lock', json=post_data)
        self.assertEqual(expected_response, response.json)
        self.assertEqual(None, self.fb_util.get_data(f"users/{TEST_USER_UID}/locks/{lock1['id']}"))
        self.assertEqual(None, self.fb_util.get_data(f"users/{TEST_USER_UID}/locks"))
        self.assertEqual(None, self.fb_util.get_data(f"authorizations/{self.door1['MAC']}/{phone_id1}"))
        self.assertEqual(None, self.fb_util.get_data(f"authorizations/{self.door1['MAC']}/{phone_id2}"))

        self.fb_util.delete_key(f"users/{TEST_USER_UID}")
        self.fb_util.delete_key(f"doors/{self.door1['MAC']}")

    def test_delete_user_lock_no_id_token(self):
        post_data = {
            'lock_id': self.door1['MAC']
        }

        expected_response = {'success': False, 'code': 403, 'msg': 'No Id Token'}
        response = self.client.post('/delete-user-lock', json=post_data)
        self.assertEqual(expected_response, response.json)

    def test_delete_user_lock_invalid_id_token(self):
        post_data = {
            'id_token': "INVALID ID TOKEN",
            'lock_id': self.door1['MAC']
        }

        expected_response = {'success': False, 'code': 403, 'msg': 'Invalid Id Token'}
        response = self.client.post('/delete-user-lock', json=post_data)
        self.assertEqual(expected_response, response.json)

    def test_delete_user_lock_no_lock_id(self):
        post_data = {
            'id_token': self.test_user_id_token
        }

        expected_response = {'success': False, 'code': 400, 'msg': 'No Lock Id'}
        response = self.client.post('/delete-user-lock', json=post_data)
        self.assertEqual(expected_response, response.json)


if __name__ == "__main__":
    unittest.main()
