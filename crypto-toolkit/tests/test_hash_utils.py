import pytest
from securecrypto import hash_utils
from argon2.exceptions import VerifyMismatchError
from argon2 import PasswordHasher

def test_hash_password_and_verify():
    pwd = "TestPass123!"   # dùng tên biến khác
    hashed = hash_utils.hash_password_secure(pwd)
    assert hashed is not None

    ph = PasswordHasher()
    try:
        ph.verify(hashed, pwd)
        verified = True
    except VerifyMismatchError:
        verified = False
    assert verified is True

def test_wrong_password_verification():
    pwd = "CorrectPass"
    wrong_pwd = "WrongPass"
    hashed = hash_utils.hash_password_secure(pwd)

    ph = PasswordHasher()
    try:
        ph.verify(hashed, wrong_pwd)
        verified = True
    except VerifyMismatchError:
        verified = False
    assert verified is False
