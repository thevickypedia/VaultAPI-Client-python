import base64
import hashlib
import json
import os
import time
from typing import Any, ByteString, Dict

import dotenv
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

env_file = os.environ.get("ENV_FILE") or os.environ.get("env_file") or ".env"
dotenv.load_dotenv(env_file)

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
    """Decrypt transit encrypted payload.

    Args:
        ciphertext: Ciphertext to decrypt.

    Returns:
        Dict[str, str]:
        Returns a dictionary of decrypted values.
    """
    epoch = int(time.time()) // TRANSIT_TIME_BUCKET
    hash_object = hashlib.sha256(f"{epoch}.{APIKEY}".encode())
    aes_key = hash_object.digest()[:TRANSIT_KEY_LENGTH]
    if isinstance(ciphertext, str):
        ciphertext = base64.b64decode(ciphertext)
    decrypted = AESGCM(aes_key).decrypt(ciphertext[:12], ciphertext[12:], b"")
    return json.loads(decrypted)


def get_cipher(server_url: str, query_params: Dict[str, str]) -> str:
    """Get ciphertext from the server.

    Args:
        server_url: Server URL to make the request to.
        query_params: Query parameters to send with the request.

    Returns:
        str:
        Returns the ciphertext.
    """
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
) -> Dict[str, str]:
    """Decrypt function.

    Args:
        cipher: Ciphertext to decrypt.
        table: Table name to retrieve.
        get_secret: Secret key to retrieve.
        get_secrets: Comma separated list of secret keys to retrieve.

    Returns:
        Dict[str, str]:
        Returns a dictionary of decrypted values.
    """
    if cipher:
        return transit_decrypt(ciphertext=cipher)
    assert all((APIKEY, VAULT_SERVER)), \
        "'APIKEY' and 'VAULT_SERVER' environment variables are required to connect to the server"
    assert table, "'table' is required when cipher text is not provided"
    params = dict(table_name=table)
    if get_secret:
        url = urljoin(VAULT_SERVER, "get-secret")
        params["key"] = get_secret
    elif get_secrets:
        url = urljoin(VAULT_SERVER, "get-secrets")
        params["keys"] = get_secrets
    else:
        url = urljoin(VAULT_SERVER, "get-table")
    return transit_decrypt(ciphertext=get_cipher(url, params))
