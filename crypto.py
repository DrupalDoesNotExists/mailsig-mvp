import datetime
from typing import Tuple

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class KeyPair:
    
    def __init__(self, privkey: rsa.RSAPrivateKey, pubkey: rsa.RSAPublicKey) -> None:
        self.privkey = privkey
        self.pubkey = pubkey


def load_pem_keys(priv: str, pub: str) -> KeyPair:
    with open(priv, 'rb') as file:
        privkey = serialization.load_pem_private_key(file.read(), password=None)
    
    with open(pub, 'rb') as file:
        pubkey = serialization.load_pem_public_key(file.read())
    
    return KeyPair(privkey, pubkey)


def create_signature(privkey: rsa.RSAPrivateKey, domain: str, ttl: datetime.timedelta) -> str:
    return jwt.encode({
        "domain": domain,
        "exp": datetime.datetime.now() + ttl
    }, privkey, algorithm="PS256")


def check_signature(pubkey: rsa.RSAPublicKey, domain: str, signature: str) -> bool:
    try:
        payload = jwt.decode(signature, pubkey, algorithms=["PS256"])
        return payload.get("domain") == domain
    except Exception:
        return False
