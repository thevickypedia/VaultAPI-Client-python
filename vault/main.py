import base64
import hashlib
import json
import os
import time
from typing import Any, ByteString, Dict

import requests
import dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

env_file = os.environ.get("ENV_FILE") or os.environ.get("env_file") or ".env"
dotenv.load_env(env_file)

VAULT_SERVER = os.environ.get("VAULT_SERVER") or os.environ.get("vault_server")
APIKEY = os.environ.get("APIKEY") or os.environ.get("apikey")

TRANSIT_TIME_BUCKET = os.environ.get("TRANSIT_TIME_BUCKET", 60)
TRANSIT_KEY_LENGTH = os.environ.get("TRANSIT_KEY_LENGTH", 60)


def urljoin(*args) -> str:
    """Joins given arguments into an url. Trailing but not leading slashes are stripped for each argument.

    Returns:
        str:
        Joined url.
    """
    return "/".join(map(lambda x: str(x).rstrip("/").lstrip("/"), args))


def transit_decrypt(ciphertext: str | ByteString) -> Dict[str, Any]:
    """Decrypt transit encrypted payload."""
    epoch = int(time.time()) // TRANSIT_TIME_BUCKET
    hash_object = hashlib.sha256(f"{epoch}.{APIKEY}".encode())
    aes_key = hash_object.digest()[:TRANSIT_KEY_LENGTH]
    if isinstance(ciphertext, str):
        ciphertext = base64.b64decode(ciphertext)
    decrypted = AESGCM(aes_key).decrypt(ciphertext[:12], ciphertext[12:], b"")
    return json.loads(decrypted)


def get_cipher(server_url: str, query_params: Dict[str, str]) -> str:
    """Get ciphertext from the server."""
    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {APIKEY}",
    }
    response = requests.get(
        server_url,
        params=query_params,
        headers=headers,
    )
    assert response.ok, response.text
    return response.json()["detail"]


def decrypt(
    cipher: str = None,
    table: str = None,
    get_secret: str = None,
    get_secrets: str = None,
):
    if not cipher:
        assert table, "table name is required when cipher text is null"
        params = {
            "table_name": table,
        }
        if not any((get_secret, get_secrets)):
            url = urljoin(VAULT_SERVER, "get-table")
        elif get_secret:
            url = urljoin(VAULT_SERVER, "get-secret")
            params["key"] = get_secret
        elif get_secrets:
            url = urljoin(VAULT_SERVER, "get-secrets")
            params["keys"] = get_secrets
        return transit_decrypt(ciphertext=get_cipher(url, params))
    return 
