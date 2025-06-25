import json
import os
import binascii  # Added for hex to bytes conversion if needed, though not directly used in final decrypt
from base64 import b64encode
from Crypto.Cipher import AES  # Not used in the final version with HSM encryption, but kept
from Crypto.Random import get_random_bytes  # Not used in the final version with HSM encryption, but kept
from Crypto.Hash import MD5  # Not used in the final version with HSM encryption, but kept

# Azure SDK imports
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import EncryptionAlgorithm
from azure.core.exceptions import ResourceNotFoundError, ClientAuthenticationError, HttpResponseError

# Askar imports (assuming these are correctly installed and used)
from aries_askar.key import Key
from aries_askar.types import KeyAlg

# --- Configuration ---
# Replace with your Azure Key Vault name or set via environment variable
# It's recommended to use a Managed HSM URL for production.
# Example: "https://<your-hsm-name>.managedhsm.azure.net/"
VAULT_URL = os.getenv("HSM_URL")
if not VAULT_URL:
    raise ValueError("HSM_URL environment variable not set. Please provide your Azure Key Vault or Managed HSM URL.")

# Name of the key in Azure Key Vault/Managed HSM
HSM_KEY_NAME = os.getenv("HSM_KEY_NAME")
if not HSM_KEY_NAME:
    raise ValueError("HSM_KEY_NAME environment variable not set. Please provide the name of your HSM key.")

# Optional: Version of the key in Azure Key Vault/Managed HSM
HSM_KEY_VERSION = os.getenv("HSM_KEY_VERSION")

# --- Azure Clients Initialization ---
try:
    # Authenticate using DefaultAzureCredential, which handles various authentication methods
    # (e.g., AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET, Managed Identity, Azure CLI)
    CREDENTIAL = DefaultAzureCredential()
    KEY_CLIENT = KeyClient(vault_url=VAULT_URL, credential=CREDENTIAL)
except ClientAuthenticationError as e:
    print(f"Authentication error initializing Azure clients: {e}")
    print("Please ensure your environment is configured for Azure authentication (e.g., Azure CLI logged in, or environment variables set).")
    exit(1)
except Exception as e:
    print(f"An unexpected error occurred during Azure client initialization: {e}")
    exit(1)

# --- Encryption Function ---
def encrypt(data: bytes, nonce: bytes) -> bytes:
    """
    Encrypts data using an AES-256 GCM key stored in Azure Key Vault/Managed HSM.

    Args:
        data: The plaintext data to encrypt.
        nonce: The Initialization Vector (IV) for AES-256 GCM. Must be 12 bytes for GCM.

    Returns:
        The ciphertext resulting from the encryption.

    Raises:
        Exception: If an error occurs during the encryption process with the HSM.
    """
    if not isinstance(data, bytes):
        raise TypeError("Input 'data' must be bytes.")
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError("Input 'nonce' must be 12 bytes.")

    try:
        # Get a cryptography client for the specified key
        crypto_client = KEY_CLIENT.get_cryptography_client(
            key_name=HSM_KEY_NAME, key_version=HSM_KEY_VERSION
        )

        # Perform the encryption using AES-256 GCM with the key in HSM
        # The plaintext is actually the data to be wrapped/encrypted by the HSM key
        result = crypto_client.encrypt(
            algorithm=EncryptionAlgorithm.a256_gcm, plaintext=data, iv=nonce
        )
        ciphertext = result.ciphertext
        return ciphertext
    except ResourceNotFoundError:
        raise Exception(
            f"Key '{HSM_KEY_NAME}' (version: {HSM_KEY_VERSION or 'latest'}) not found in '{VAULT_URL}'. "
            "Please ensure the key exists and you have appropriate permissions."
        )
    except ClientAuthenticationError as e:
        raise Exception(f"Authentication error during encryption: {e}. Check your credentials.")
    except HttpResponseError as e:
        raise Exception(f"Azure Key Vault/HSM service error during encryption: {e}. Status: {e.status_code}.")
    except Exception as e:
        raise Exception(f"An unexpected error occurred during encryption: {e}")

# --- Decryption Function ---
def decrypt(ciphertext: bytes, nonce: bytes) -> bytes:
    """
    Decrypts ciphertext using an AES-256 GCM key stored in Azure Key Vault/Managed HSM.

    Args:
        ciphertext: The encrypted data to decrypt.
        nonce: The Initialization Vector (IV) used during encryption. Must be 12 bytes for GCM.

    Returns:
        The plaintext resulting from the decryption.

    Raises:
        Exception: If an error occurs during the decryption process with the HSM.
    """
    if not isinstance(ciphertext, bytes):
        raise TypeError("Input 'ciphertext' must be bytes.")
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError("Input 'nonce' must be 12 bytes.")

    try:
        # Get a cryptography client for the specified key
        crypto_client = KEY_CLIENT.get_cryptography_client(
            key_name=HSM_KEY_NAME, key_version=HSM_KEY_VERSION
        )

        # Perform the decryption using AES-256 GCM with the key in HSM
        result = crypto_client.decrypt(
            algorithm=EncryptionAlgorithm.a256_gcm, ciphertext=ciphertext, iv=nonce
        )
        plaintext = result.plaintext
        return plaintext
    except ResourceNotFoundError:
        raise Exception(
            f"Key '{HSM_KEY_NAME}' (version: {HSM_KEY_VERSION or 'latest'}) not found in '{VAULT_URL}'. "
            "Please ensure the key exists and you have appropriate permissions."
        )
    except ClientAuthenticationError as e:
        raise Exception(f"Authentication error during decryption: {e}. Check your credentials.")
    except HttpResponseError as e:
        # This could indicate an invalid ciphertext, IV, or tag if the HSM returns an error
        raise Exception(f"Azure Key Vault/HSM service error during decryption: {e}. Status: {e.status_code}. "
                        "This might indicate invalid ciphertext, IV, or authentication tag.")
    except Exception as e:
        raise Exception(f"An unexpected error occurred during decryption: {e}")

# --- Check HSM Key Function ---
def check_hsm_key(from_key_entry, seed: str) -> Key:
    """
    Checks if a key entry is HSM-enabled and decrypts it using the HSM if necessary.

    Args:
        from_key_entry: An object containing key data and metadata (e.g., from an Askar wallet).
                        Expected to have 'key' (with get_secret_bytes method) and 'metadata'.
        seed: A string seed used to derive the nonce for decryption.

    Returns:
        The decrypted Key object.

    Raises:
        ValueError: If the seed is too short for nonce generation.
        Exception: If decryption fails.
    """
    if not isinstance(seed, str):
        raise TypeError("Input 'seed' must be a string.")
    if len(seed) < 24: # Minimum length for 12-byte nonce
        raise ValueError("Seed must be at least 24 characters long to derive a 12-byte nonce.")

    # Accessing key and metadata safely
    key_obj = from_key_entry.key
    try:
        meta = json.loads(from_key_entry.metadata)
    except (json.JSONDecodeError, AttributeError):
        meta = {} # Default to empty dict if metadata is missing or invalid JSON

    if meta.get("hsm_enabled"):
        # The nonce for AES-GCM should be 12 bytes (96 bits).
        # We are deriving it from the seed for consistency.
        nonce = seed[:12].encode('utf-8') # Take first 12 characters and encode to bytes
        # Ensure nonce is exactly 12 bytes; pad with zeros if necessary, or raise error if too short
        if len(nonce) < 12:
            raise ValueError("Derived nonce from seed is less than 12 bytes. Adjust seed or nonce derivation.")
        elif len(nonce) > 12:
             nonce = nonce[:12] # Truncate if too long, though `seed[:12]` should prevent this if seed is string of chars.

        try:
            # Assuming key_obj.get_secret_bytes() returns the wrapped key bytes
            # The Askar Key type (KeyAlg.ED25519) should be chosen based on what's wrapped.
            decrypted_secret_key = decrypt(ciphertext=key_obj.get_secret_bytes(), nonce=nonce)
            key_obj = Key.from_secret_bytes(KeyAlg.ED25519, decrypted_secret_key)
        except Exception as e:
            raise Exception(f"Failed to decrypt HSM-enabled key: {e}")
    return key_obj