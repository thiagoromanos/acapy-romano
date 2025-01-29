import json
import os
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import MD5
from aries_askar.key import Key
from aries_askar.types import KeyAlg
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient, KeyType
from azure.keyvault.secrets import SecretClient

# Replace with your Azure Key Vault name
key_vault_name = os.getenv("AZURE_VAULT_NAME", "")
vault_url = f"https://{key_vault_name}.vault.azure.net/"

# Initialize the Key Client
credential = DefaultAzureCredential()
# TODO: get this value from a env var
secret_name = os.getenv("AZURE_SECRET_NAME", "chave123") 

def encrypt(data: bytes, nonce: bytes, key: bytes):
    # header = b"askar"

    # data = b"secret"

    # key = get_random_bytes(16)
    # nonce = get_random_bytes(12)
    secret_client = SecretClient(vault_url=vault_url, credential=credential)
    key_hex = secret_client.get_secret(secret_name)
    key = bytes.fromhex(key_hex.value)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

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
        # using the seed's hash as key
        # _hash = MD5.new(seed.encode()).hexdigest()
        secret_client = SecretClient(vault_url=vault_url, credential=credential)
        _hash = secret_client.get_secret(secret_name)                    
        _hash = bytes.fromhex(_hash.value)
        sk = decrypt(ciphertext=key.get_secret_bytes(), nonce=nonce.encode(), key=_hash) 
        key = Key.from_secret_bytes(KeyAlg.ED25519, sk)
    return key                                    