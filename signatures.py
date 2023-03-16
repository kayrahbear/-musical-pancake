import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open('private_key.pem', 'wb') as f:
        f.write(private_pem)

    with open('public_key.pem', 'wb') as f:
        f.write(public_pem)

    return private_key, public_key


def sign_message(message, private_key):
    message_byte = message.encode("utf-8")
    signature = private_key.sign(
        message_byte,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def verify_signature(message, signature):
    message_byte = message.encode("utf-8")

    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),

        )

    try:
        public_key.verify(signature, message_byte,
                          padding.PSS(
                              mgf=padding.MGF1(hashes.SHA256()),
                              salt_length=padding.PSS.MAX_LENGTH
                          ),
                          hashes.SHA256()
                          )
    except InvalidSignature:
        return False

    return True


# we testing in the same file

class TestSignatures(unittest.TestCase):
    def test_generate_keys(self):
        private_key, public_key = generate_keys()
        self.assertTrue(private_key, public_key)

    def test_sign_message(self):
        private_key, _ = generate_keys()
        signature = sign_message("test", private_key)
        self.assertEqual(len(signature), 256)

    def test_verify_signature(self):
        private_key, public_key = generate_keys()
        signature = sign_message("test", private_key)
        signature_response = verify_signature("test", signature)
        self.assertTrue(signature_response)


if __name__ == '__main__':
    unittest.main()
