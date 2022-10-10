import unittest

from firebase_util_for_tests import FirebaseUtilForTests
from rsa_util import RSA_Util, get_rsa_key_from_x509_cert


class TestRSAUtilMethods(unittest.TestCase):
    RSA_PUB_KEY_STR = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxLHVaTHF5D1Jm/+5n+YH
/Ci0QLAg/2nmyyW+QwNHZYNWc93rQSRumjgv4Imi1kUGtpqu7PsmStGtFWlXUsaB
HIgWEhBkXY1tyHv4l3r0NpFWephUER+ED8Uo90+sjrF4VycZAh7AS7SuMRTSJh7p
rzV7N3Htl4GHfGUD3Kdii90uYIKPSq2nFOWoBzcSK6QmtnkQb3yw4zb6cVUjoBD7
qPYezx9VKY/gYy7qGNq9vooKXOdHse7oLCZ+5O0QbeaPY53aLuJbs2KJtTr0iwEm
yA2ELJKs3fQiVEKeitbAybOk/2mvgCXQcQLrN1H2rl/cpEYN6f6qJxjgPTktt+dn
kQIDAQAB
-----END PUBLIC KEY-----'''

    RSA_PRIV_KEY_STR = '''-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAnXR6vNoSs0yYrNYF69R5eGrvPEwcYbXcmhj+KgUaY1rYi9H8
L853mxaVHifKqHjSMsRSOBe/IFfZ30fBhMNP3OUB63BiOK1Rlz9Tgxj6WFLGb6gk
E20Y5c0WvgyN7MK08ER5beeq6eFILA3j4HRNPD0z7015kub85M7oJHluuCpLYTGZ
u+u5tyRJTEapj48EcydbB8oHkjt12a1Q2myUp6maFGTZ1Q0lOFaR1oob9z7h/U+j
tn7juOlnXJLqvZ8oDWLSSqvV9u5hwvnCgLjY7yUXDTbxaHaYu7AwksfqomTES1r7
Ktvh63W6MstNeGg8r2ymmCw2gO2Ddms8zPUDaQIDAQABAoIBAC5cmrs6tuDmf9n8
Vtf+wxmK2xB1FLJMmz0geM4knIV+vV5GISxubddTierMKqb6lGHwXok3rMY4N+W/
uiJ+Y+iV4b/SYolvtyOCuPNUCnqxPM6pwp2ZtQgNIFIrXirFlgNdFigfW7rr45Vd
LajsdcVz+/PNayuvKe2xYrdCrjA5haY62cayi3cev4KySxBgeX9F9iXGsMQt3ko5
TqSTkk7Okanz2srtDrwiXyOSyN73wvRYJKzJCfbOfpaViCKNpYu2Uy8vQmxrLmxk
Ht+7/KpC22oQpVHS9aOXQbZoFcP4tBOvnUvoyd1OwcN8JMVlLabE8aXtsdk/al+V
5CTDeVUCgYEAyh8Ho40XWDfo6KKoT+c3SNmrmV9qHBPVgOn0v0u/BUjtNio4lrnF
0K3vBgs1q2YQ+i81c9OnJd6scz57N9vl8foWmkKsjhyj5VuzaY10iZodnShpCai7
1WyEHikP4zZwrqMu+JCi6b0LGzmYOMwZYh9SnDIcO2a0QD6PAbL9f7cCgYEAx21h
AOUT82rntjzWYIVJNTcUw7esQqRRd6XtAxeLLOA+RkVYanGvIV60LpKXQZgpiros
zKexKqABlOQT0MGfNTwesLVGnmtt/RsGrc2y0B5CSj4BlfFQuBruSWSdMF/BaBoU
nzRL3Rp+2eYwrRiJBqJf8tN93mGy9Z+gN7kdVd8CgYBYY8F/cJAo8CpWsetRJhgz
L52vcN6CcNoJikaR8ZoTwZSa/1PH9m3fmHDS/8v0rKn3/vUtNf3+vaZEr6pK/0tL
ysZfp5C2hSfXgYawPkAcfN0+gRGOO9AIwW/1kJd2EbStaod8BCR6e0WEHmfHTto6
4t/JltBp2bwx7Cm14ISjeQKBgHL1GB+97Vw52cvxEdqdum+UisGvVPstYVDJMvC/
V5jMwtkbDDZ/xeZEgzT9h3dmUTwIyd5HJBdgGMlNGCcUFcRIHaDbPhP/9W0bcSQr
GNJjPu8xAxT9//vAem+QMhQ6fnCV6CFFsh2IMmtFB/Yf2I0ceJavVzUjuFdiZqb4
bHKdAoGBAKKAkTBXUS/vfAJvdlwTpa3IRKZKktjGWvlpNVNU8bYo7xQGXpEEXugg
Q25wRWKI10hwG0cYRiVbiwIxqoYqF+4SGGoQBZ3/XhXSdBfGG6UC53hESl7rRO5W
ymIEhdLR7VqY2PkHcU2GChWxpf2IhUwlJYP+er10dKFvSUHxivHB
-----END RSA PRIVATE KEY-----'''

    def test_rsa_init_with_filename(self):
        rsa = RSA_Util(filename="../public_key.pem")
        self.assertEqual(rsa.key.exportKey().decode(), self.RSA_PUB_KEY_STR)

    def test_rsa_init_with_key_str(self):
        rsa = RSA_Util(key_str=self.RSA_PUB_KEY_STR)
        self.assertEqual(rsa.key.exportKey().decode(), self.RSA_PUB_KEY_STR)

    def test_get_rsa_key_from_x509_cert(self):
        cert = f"-----BEGIN CERTIFICATE-----MIIDnDCCAoQCFCgMck/fiKWOmeNKNcQTKI66xXUEMA0GCSqGSIb3DQEBCwUAMIGqMQswCQYDVQQGEwJQVDEPMA0GA1UECAwGTGlzYm9uMQ8wDQYDVQQHDAZMaXNib24xHTAbBgNVBAoMFE1TYyBCZXJuYXJkbyBNYXJxdWVzMQswCQYDVQQLDAJDQTEZMBcGA1UEAwwQQmVybmFyZG8gTWFycXVlczEyMDAGCSqGSIb3DQEJARYjYmVybmFyZG9jbWFycXVlc0B0ZWNuaWNvLnVsaXNib2EucHQwHhcNMjIwNDI1MTQ1ODU1WhcNMjMwNDI1MTQ1ODU1WjBqMQswCQYDVQQGEwJQVDEPMA0GA1UECAwGTGlzYm9uMQ8wDQYDVQQHDAZMaXNib24xHTAbBgNVBAoMFE1TYyBCZXJuYXJkbyBNYXJxdWVzMRowGAYDVQQDDBE3QzpERjpBMToxQTowRTo1QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMSx1WkxxeQ9SZv/uZ/mB/wotECwIP9p5sslvkMDR2WDVnPd60Ekbpo4L+CJotZFBraaruz7JkrRrRVpV1LGgRyIFhIQZF2Nbch7+Jd69DaRVnqYVBEfhA/FKPdPrI6xeFcnGQIewEu0rjEU0iYe6a81ezdx7ZeBh3xlA9ynYovdLmCCj0qtpxTlqAc3EiukJrZ5EG98sOM2+nFVI6AQ+6j2Hs8fVSmP4GMu6hjavb6KClznR7Hu6CwmfuTtEG3mj2Od2i7iW7NiibU69IsBJsgNhCySrN30IlRCnorWwMmzpP9pr4Al0HEC6zdR9q5f3KRGDen+qicY4D05LbfnZ5ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAVIZYs/w7f+m8df7ceUFkR6mfWZDMr+NrBwsKfoM3ezlgQUcmcezYuRadvn94KxDw2QL65d0vQvTCVFSXOnbb1wQktXrRtueo9Dat+rwMccOORq2lMO1B/zrhjXSNVh4Aou2fzvNJXC5yC3sAnKfBMDEhxvsct+jT+MogCXKh7r8gRHErY2FoEDge9RvkWDZFqIOeLt8/juALdOjsU+XDaKK6oAb+N4pVun7KxiXFussoX/3bf3y6kVLwUmvse9OhmXt4R7jV1jn6kFUpYetqhrAQcvP5Id3fc3op+su0j51RgHZ5n2tKirR9TgauTvo8Ag5JM5mL3bllWdI2wnSmlA==-----END CERTIFICATE-----"

        rsa = RSA_Util(key_str=get_rsa_key_from_x509_cert(cert))
        self.assertEqual(rsa.key.exportKey().decode(), self.RSA_PUB_KEY_STR)

    def test_encrypt_and_decrypt_msg_ok(self):
        rsa = RSA_Util(key_str=self.RSA_PRIV_KEY_STR)
        plaintext = "This is a plaintext message!"

        encrypted_message_b64 = rsa.encrypt_msg(plaintext)
        decrypted_message = rsa.decrypt_msg(encrypted_message_b64).decode()
        self.assertEqual(decrypted_message, plaintext)

    def test_decrypt_msg_with_pub_key(self):
        rsa = RSA_Util(key_str=self.RSA_PUB_KEY_STR)
        plaintext = "This is a plaintext message!"

        encrypted_message_b64 = rsa.encrypt_msg(plaintext)
        decrypted_message = rsa.decrypt_msg(encrypted_message_b64)
        self.assertEqual(decrypted_message, None)

    def test_encrypt_and_decrypt_msg_wrong_plaintext(self):
        rsa = RSA_Util(key_str=self.RSA_PUB_KEY_STR)
        plaintext = "This is a plaintext message!"
        plaintext_wrong = "This is the wrong plaintext message!"

        encrypted_message_b64 = rsa.encrypt_msg(plaintext_wrong)
        decrypted_message = rsa.decrypt_msg(encrypted_message_b64)
        self.assertNotEqual(decrypted_message, plaintext)

    def test_sing_and_is_signature_valid_ok(self):
        rsa = RSA_Util(key_str=self.RSA_PRIV_KEY_STR)
        message = "This is a message!"

        signature_b64 = rsa.sign(message)
        is_valid = rsa.is_signature_valid(message, signature_b64)
        self.assertTrue(is_valid)

    def test_sing_and_is_signature_valid_invalid_message(self):
        rsa = RSA_Util(key_str=self.RSA_PRIV_KEY_STR)
        message = "This is a message!"
        message_invalid = "This is a invalid message!"

        signature_b64 = rsa.sign(message)
        is_valid = rsa.is_signature_valid(message_invalid, signature_b64)
        self.assertFalse(is_valid)


if __name__ == '__main__':
    unittest.main()
