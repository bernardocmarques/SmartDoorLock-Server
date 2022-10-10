import firebase_admin
from firebase_admin import credentials, db
import string

from firebase_util import generate_random_id

characters = string.ascii_letters + string.digits

TEST_ENV_PATH = "test_env/"

ID_TOKEN_VALID = "ID_TOKEN_VALID"
ID_TOKEN_NOT_VALID = "ID_TOKEN_NOT_VALID"


class FirebaseUtilForTests:

    def __init__(self):
        _cred = credentials.Certificate("firebase_credentials.json")
        firebase_admin.initialize_app(_cred, {
            'databaseURL': 'https://smartdoorlock-16418-default-rtdb.europe-west1.firebasedatabase.app'
        })

        self.db = db

    def get_data(self, path):
        ref = self.db.reference(TEST_ENV_PATH + path)
        return ref.get()

    def set_data(self, path, data):
        ref = self.db.reference(TEST_ENV_PATH + path)
        ref.update(data)
        return True

    def delete_key(self, path):
        ref = self.db.reference(TEST_ENV_PATH + path)
        ref.delete()
        return True

    def add_data_to_path(self, path, data):
        ref = self.db.reference(f"{TEST_ENV_PATH}{path}/{generate_random_id(8)}")
        ref.update(data)
        return True

    def get_data_where_child_equal_to(self, path, child, value):
        ref = self.db.reference(TEST_ENV_PATH + path)
        return ref.order_by_child(child).equal_to(value).limit_to_first(1).get()

    def set_random_username(self, user_id):
        ref = self.db.reference(f"{TEST_ENV_PATH}users/{user_id}")
        username = generate_random_id(15)
        ref.update({
            'username': username
        })
        return username
