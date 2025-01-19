import base64
import hashlib
import json
import os
import time
from typing import Any, ByteString, Dict

import dotenv
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vaultapi.aws import LOGGER, AWSClient  # noqa: F401

env_file = os.environ.get("ENV_FILE") or os.environ.get("env_file") or ".env"
dotenv.load_dotenv(env_file)


class VaultAPIClientError(Exception):
    """Base error class for the VaultAPI Client."""


def urljoin(*args) -> str:
    """Joins given arguments into an url. Trailing but not leading slashes are stripped for each argument.

    Returns:
        str:
        Joined url.
    """
    return "/".join(map(lambda x: str(x).rstrip("/").lstrip("/"), args))


class EnvConfig:
    """Wrapper for env configuration.

    >>> EnvConfig

    """

    def __init__(self, **kwargs):
        """Instantiates the env config."""
        self.vault_server = kwargs.get("vault_server")
        self.vault_apikey = kwargs.get("vault_apikey")
        self.vault_secret = kwargs.get("vault_secret")
        self.transit_time_bucket = int(kwargs.get("vault_transit_time_bucket"))
        self.transit_key_length = int(kwargs.get("vault_transit_key_length"))


def getenv(key: str, default: str = None) -> str:
    """Returns the key-ed environment variable or the default value."""
    return os.environ.get(key.upper()) or os.environ.get(key.lower()) or default


def resolve_secrets(try_aws: bool):
    """Tries to retrieve the required secret from environment variable or AWS parameter or the AWS secrets manager."""
    base_env_vars = dict(
        vault_server=getenv("vault_server"),
        vault_apikey=getenv("vault_apikey"),
        vault_secret=getenv("vault_secret"),
        vault_transit_time_bucket=getenv("vault_transit_time_bucket", "60"),
        vault_transit_key_length=getenv("vault_transit_key_length", "60"),
    )
    if all(base_env_vars.values()):
        return EnvConfig(**base_env_vars)
    unsatisfied = [k for k, v in base_env_vars.items() if not v]
    if try_aws:
        aws_client = AWSClient()
        resolved_env_vars = {
            **base_env_vars,
            **{
                k: aws_client.get_aws_params(k) or aws_client.get_aws_secrets(k)
                for k in unsatisfied
            },
        }
        if all(resolved_env_vars.values()):
            return EnvConfig(**resolved_env_vars)
        unsatisfied = [k for k, v in resolved_env_vars.items() if not v]
    raise VaultAPIClientError(f"Not all required values were satisfied: {unsatisfied}")


class VaultAPIClient:
    """Vault API client object to retrieve secrets from the VaultAPI Server.

    >>> VaultAPIClient

    """

    def __init__(self, aws: bool = getenv("vault_aws", "0") in ("1", "true")):
        """Instantiates the VaultAPIClient object."""
        self.env_config = resolve_secrets(aws)
        self.SESSION = requests.Session()
        self.SESSION.headers = {
            "accept": "application/json",
            "Authorization": f"Bearer {self.env_config.vault_apikey}",
        }

    def transit_decrypt(self, ciphertext: str | ByteString) -> Dict[str, Any]:
        """Decrypt transit encrypted payload.

        Args:
            ciphertext: Ciphertext to decrypt.

        Returns:
            Dict[str, str]:
            Returns a dictionary of decrypted values.
        """
        assert self.env_config.vault_secret, (
            "\n\t'SECRET' environment variable is required to decrypt the cipher!"
            "\n\tSet 'RAW_CIPHER=1' to skip transit decryption"
        )
        epoch = int(time.time()) // self.env_config.transit_time_bucket
        serialized = (
            f"{epoch}.{self.env_config.vault_apikey}.{self.env_config.vault_secret}"
        )
        encoded = serialized.encode()
        hash_object = hashlib.sha256(encoded)
        aes_key = hash_object.digest()[: self.env_config.transit_key_length]
        if isinstance(ciphertext, str):
            ciphertext = base64.b64decode(ciphertext)
        decrypted = AESGCM(aes_key).decrypt(ciphertext[:12], ciphertext[12:], b"")
        return json.loads(decrypted)

    def get_cipher(self, server_url: str, query_params: Dict[str, str]) -> str:
        """Get ciphertext from the server.

        Args:
            server_url: Server URL to make the request to.
            query_params: Query parameters to send with the request.

        Returns:
            str:
            Returns the ciphertext.
        """
        response = self.SESSION.get(
            server_url,
            params=query_params,
        )
        assert response.ok, response.text
        return response.json()["detail"]

    def update_secret(self, key: str, value: str, table_name: str) -> Dict[str, str]:
        """Update or create a new secret in the vault.

        Args:
            key: Key for the secret.
            value: Value for the secret.
            table_name: Table name.

        Returns:
            Dict[str, str]:
            Returns the server response.
        """
        url = urljoin(self.env_config.vault_server, "put-secret")
        response = self.SESSION.put(
            url,
            json={
                "key": key,
                "value": value,
                "table_name": table_name,
            },
        )
        assert response.ok, response.text
        return response.json()["detail"]

    def delete_secret(self, key: str, table_name: str) -> Dict[str, str]:
        """Delete a secret from the vault.

        Args:
            key: Key for the secret.
            table_name: Table name.

        Returns:
            Dict[str, str]:
            Returns the server response.
        """
        url = urljoin(self.env_config.vault_server, "delete-secret")
        response = self.SESSION.delete(
            url,
            json={
                "key": key,
                "table_name": table_name,
            },
        )
        assert response.ok, response.text
        return response.json()["detail"]

    def create_table(self, table_name: str) -> Dict[str, str]:
        """Creates a new table in the vault.

        Args:
            table_name: Table name.

        Returns:
            Dict[str, str]:
            Returns the server response.
        """
        url = urljoin(self.env_config.vault_server, "create-table")
        response = self.SESSION.post(url, params={"table_name": table_name})
        assert response.ok, response.text
        return response.json()["detail"]

    def decrypt(
        self,
        table: str,
        get_secret: str = None,
        get_secrets: str = None,
        raw_cipher: bool = os.environ.get("RAW_CIPHER", "").lower() in ("1", "true"),
    ) -> Dict[str, str] | str:
        """Decrypt function.

        Args:
            table: Table name to retrieve.
            get_secret: Secret key to retrieve.
            get_secrets: Comma separated list of secret keys to retrieve.
            raw_cipher: Boolean flag to return the raw cipher without transit decryption.

        Returns:
            Dict[str, str]:
            Returns a dictionary of decrypted values.
        """
        if not table:
            LOGGER.warning("No table_name was given")
            return {}
        params = dict(table_name=table)
        if get_secret:
            url = urljoin(self.env_config.vault_server, "get-secret")
            params["key"] = get_secret
        elif get_secrets:
            url = urljoin(self.env_config.vault_server, "get-secrets")
            params["keys"] = get_secrets
        else:
            url = urljoin(self.env_config.vault_server, "get-table")
        cipher_text = self.get_cipher(url, params)
        if raw_cipher:
            return cipher_text
        return self.transit_decrypt(cipher_text)
