import json
import os

import firebase_admin
from firebase_admin import credentials, auth, db
from firebase_admin.auth import InvalidIdTokenError, InvalidSessionCookieError
from firebase_admin.exceptions import FirebaseError
import secrets


class FirebaseUtil:

    def __init__(self):
        _cred = credentials.Certificate("firebase_credentials.json")
        firebase_admin.initialize_app(_cred, {
            'databaseURL': 'https://smartdoorlock-16418-default-rtdb.europe-west1.firebasedatabase.app'
        })

        self.db = db

    def delete_key(self, path):
        ref = self.db.reference(path)
        ref.delete()
        return True

    def set_data(self, path, data):
        ref = self.db.reference(path)
        ref.update(data)
        return True

    def add_data_to_path(self, path, data):
        ref = self.db.reference(f"{path}/{generate_random_id(8)}")
        ref.update(data)
        return True

    def get_data(self, path):
        ref = self.db.reference(path)
        return ref.get()


def generate_random_id(n):
    return secrets.token_urlsafe(n)


def get_decoded_claims_id_token(id_token, **kwargs):
    try:
        return auth.verify_id_token(id_token, **kwargs)
    except:
        return None


def check_if_admin(id_token):
    return not not get_decoded_claims_id_token(id_token).get("admin")


def check_if_user(id_token):
    return not not get_decoded_claims_id_token(id_token)
