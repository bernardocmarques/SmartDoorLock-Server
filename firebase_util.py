import json
import os

import firebase_admin
from firebase_admin import credentials, auth, db
from firebase_admin.auth import InvalidIdTokenError, InvalidSessionCookieError
from firebase_admin.exceptions import FirebaseError
import random
import string

characters = string.ascii_letters + string.digits


class FirebaseUtil:

    def __init__(self):
        _cred = credentials.Certificate("firebase_credentials.json")
        firebase_admin.initialize_app(_cred, {
            'databaseURL': 'https://smartdoorlock-16418-default-rtdb.europe-west1.firebasedatabase.app'
        })

        self.db = db

    def get_data(self, path):
        ref = self.db.reference(path)
        return ref.get()

    def set_data(self, path, data):
        ref = self.db.reference(path)
        ref.update(data)
        return True

    def delete_key(self, path):
        ref = self.db.reference(path)
        ref.delete()
        return True

    def add_data_to_path(self, path, data):
        ref = self.db.reference(f"{path}/{generate_random_id(8)}")
        ref.update(data)
        return True

    def get_data_where_child_equal_to(self, path, child, value):
        ref = self.db.reference(path)
        return ref.order_by_child(child).equal_to(value).limit_to_first(1).get()

    def set_random_username(self, user_id):
        ref = self.db.reference(f"users/{user_id}")
        username = generate_random_id(15)
        ref.update({
            'username': username
        })
        return username


def generate_random_id(n):
    return ''.join(random.choice(characters) for _ in range(n))


def get_decoded_claims_id_token(id_token, **kwargs):
    try:
        return auth.verify_id_token(id_token, **kwargs)
    except:
        return None


def check_if_admin(id_token):
    return not not get_decoded_claims_id_token(id_token).get("admin")


def check_if_user(id_token):
    return not not get_decoded_claims_id_token(id_token)
