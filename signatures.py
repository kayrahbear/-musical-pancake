import unittest


def generate_keys():
    pass


def sign_message(message, private_key):
    pass


def verify_signature(message, signature):
    pass


# we testing in the same file

class TestSignatures(unittest.TestCase):
    def test_generate_keys(self):
        private_key, public_key = generate_keys()
        self.assertEqual(len(private_key), 32)

    def test_sign_message(self):
        signature = sign_message('test', 'test')
        self.assertEqual(len(signature), 64)

    def test_verify_signature(self):
        signature_response = verify_signature('test', 'test')
        self.assertTrue(signature_response)



