import json

from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import MD5
from aries_askar.key import Key
from aries_askar.types import KeyAlg

def encrypt(data: bytes, nonce: bytes, key: bytes):
    # header = b"askar"

    # data = b"secret"

    # key = get_random_bytes(16)
    # nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # bytes.fromhex(key)

    # cipher.update(header)

    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext
    # json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]

    # json_v = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag) ]

    # result = json.dumps(dict(zip(json_k, json_v)))

    # return result

def decrypt(ciphertext: bytes, nonce: bytes, key: bytes):
    try: 
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext
    except (ValueError, KeyError):
        raise("Error on decrypting")
    

def check_hsm_key(from_key_entry, seed: str):
    key = from_key_entry.key
    meta = json.loads(from_key_entry.metadata)
    if meta.get("hsm_enabled"):
        # seed = session.settings.get('wallet.seed')
        nonce = seed[:24] # 12-byte nonce
        _hash = MD5.new(seed.encode()).hexdigest()                    
        sk = decrypt(ciphertext=key.get_secret_bytes(), nonce=nonce.encode(), key=_hash.encode()) 
        key = Key.from_secret_bytes(KeyAlg.ED25519,sk)
    return key                                    