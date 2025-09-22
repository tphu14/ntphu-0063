import pytest
from securecrypto import rsa_utils

def test_rsa_keypair_generation():
    priv, pub = rsa_utils.generate_rsa_keypair()
    assert priv is not None
    assert pub is not None

def test_sign_and_verify():
    priv, pub = rsa_utils.generate_rsa_keypair()
    data = b"Test data for signing"
    signature = rsa_utils.sign_data_rsa(data, priv)
    assert rsa_utils.verify_signature_rsa(data, signature, pub) == True