import unittest


from firebase_util import generate_random_id, get_decoded_claims_id_token
from firebase_util_for_tests import FirebaseUtilForTests


class TestFirebaseUtilMethods(unittest.TestCase):
    fb_util = FirebaseUtilForTests()
    fb_util.delete_key("")

    def test_set_data_ok(self):
        data = {
            'arg_string': "string",
            'arg_bool': False,
            'arg_int': 1,
            'arg_float': 0.5,
        }

        self.assertTrue(self.fb_util.set_data("path/key", data))
        self.fb_util.delete_key("path/key")

    def test_get_data_ok(self):
        data = {
            'arg_string': "string",
            'arg_bool': False,
            'arg_int': 1,
            'arg_float': 0.5,
        }

        self.fb_util.set_data("path/key", data)
        self.assertEqual(self.fb_util.get_data(f"path/key"), data)
        self.fb_util.delete_key(f"path/key")

    def test_delete_data_ok(self):
        data = {
            'arg_string': "string",
            'arg_bool': False,
            'arg_int': 1,
            'arg_float': 0.5,
        }

        self.fb_util.set_data("path/key", data)
        self.fb_util.delete_key(f"path/key")
        self.assertEqual(self.fb_util.get_data(f"path/key"), None)

    def test_add_data_to_path_ok(self):
        data = {
            'arg_string': "string",
            'arg_bool': False,
            'arg_int': 1,
            'arg_float': 0.5,
        }

        self.fb_util.add_data_to_path("path", data)
        self.assertEqual(list(self.fb_util.get_data("path").values())[0], data)
        self.fb_util.delete_key(f"path")

    # def test_get_data_where_child_equal_to_ok(self):
    #     data = {
    #         'arg_string': "string",
    #         'arg_bool': False,
    #         'arg_int': 1,
    #         'arg_float': 0.5,
    #     }
    #
    #     data_to_find = {
    #         'arg_string': "string_to_find",
    #         'arg_bool': False,
    #         'arg_int': 1,
    #         'arg_float': 0.5,
    #     }
    #
    #     self.fb_util.add_data_to_path("path", data)
    #     self.fb_util.add_data_to_path("path", data_to_find)
    #
    #     self.assertEqual(self.fb_util.get_data_where_child_equal_to("path", "arg_string", "string_to_find"), data)
    #     self.fb_util.delete_key(f"path")

    def test_set_random_username_ok(self):
        user_id = "123456789abc"
        username = self.fb_util.set_random_username(user_id)

        self.assertEqual(self.fb_util.get_data(f"users/{user_id}/username"), username)
        self.fb_util.delete_key(f"users")

    def test_generate_random_id_small_n(self):
        rand_id = generate_random_id(5)

        self.assertIsInstance(rand_id, str)
        self.assertEqual(len(rand_id), 5)

    def test_generate_random_id_big_n(self):
        rand_id = generate_random_id(100)

        self.assertIsInstance(rand_id, str)
        self.assertEqual(len(rand_id), 100)

    def test_generate_random_id_n_equal_to_1(self):
        rand_id = generate_random_id(1)

        self.assertIsInstance(rand_id, str)
        self.assertEqual(len(rand_id), 1)

    def test_generate_random_id_n_equal_to_0(self):
        rand_id = generate_random_id(0)

        self.assertIsInstance(rand_id, str)
        self.assertEqual(rand_id, "")
        self.assertEqual(len(rand_id), 0)

    def test_generate_random_id_negative_n(self):
        rand_id = generate_random_id(-1)

        self.assertIsInstance(rand_id, str)
        self.assertEqual(rand_id, "")
        self.assertEqual(len(rand_id), 0)


if __name__ == '__main__':
    unittest.main()
