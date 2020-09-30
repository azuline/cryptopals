import re
from secrets import token_bytes as random_bytes

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

QS_SPLITTER = re.compile(r"(?<!\\)\&")
KV_SPLITTER = re.compile(r"(?<!\\)\=")


def key_val_parse(query_string):
    return dict(KV_SPLITTER.split(pair) for pair in QS_SPLITTER.split(query_string))


def profile_for(email, uid="10", role="user"):
    email = escape(email)
    role = escape(role)
    return "&".join(
        ["=".join([k, v]) for k, v in {"email": email, "uid": uid, "role": role}.items()]
    )


def escape(string):
    return string.replace("&", r"\&").replace("=", r"\=")


def encrypt_profile(email):
    key = random_bytes(16)
    iv = random_bytes(16)
    cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
    return key, iv, cipher.encrypt(pad(profile_for(email).encode(), 16))


def decrypt_profile(key, iv, encrypted_profile):
    cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv)
    return key_val_parse(unpad(cipher.decrypt(encrypted_profile), 16).decode())


if __name__ == "__main__":
    assert key_val_parse(r"foo=ba\=\&r&baz=qux&zap=zazzle") == {
        "foo": r"ba\=\&r",
        "baz": "qux",
        "zap": "zazzle",
    }

    assert profile_for("foo@foo.bar&role=admin") == (
        r"email=foo@foo.bar\&role\=admin&uid=10&role=user"
    )

    assert decrypt_profile(*encrypt_profile("foo@bar.baz")) == {
        "email": "foo@bar.baz",
        "uid": "10",
        "role": "user",
    }

    print("Passed")
