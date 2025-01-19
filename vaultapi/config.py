import os

import dotenv
import requests
from cryptography.fernet import Fernet

from vaultapi.aws import AWSClient
from vaultapi.exceptions import VaultAPIClientError
from vaultapi.util import urljoin

env_file = os.environ.get("ENV_FILE") or os.environ.get("env_file") or ".env"
dotenv.load_dotenv(env_file)


class EndpointMapping:
    """Enum like function to get all endpoint names to avoid hard coding.

    >>> EndpointMapping

    """

    health: str = "/health"
    get_table: str = "/get-table"
    get_secret: str = "/get-secret"
    put_secret: str = "/put-secret"
    get_secrets: str = "/get-secrets"
    put_secrets: str = "/put-secrets"
    list_tables: str = "/list-tables"
    create_table: str = "/create-table"
    delete_secret: str = "/delete-secret"


server_map = EndpointMapping()


class EnvConfig:
    """Wrapper for env configuration.

    >>> EnvConfig

    """

    def __init__(self, **kwargs):
        """Instantiates the env config."""
        self.vault_server: str = kwargs.get("vault_server")
        self.vault_apikey: str = kwargs.get("vault_apikey")
        self.vault_secret: str = kwargs.get("vault_secret")
        self.transit_time_bucket: int = int(kwargs.get("vault_transit_time_bucket"))
        self.transit_key_length: int = int(kwargs.get("vault_transit_key_length"))
        self.__assert__()

    def __assert__(self):
        """Run assertions for server config."""
        response = requests.get(url=urljoin(self.vault_server, server_map.health))
        assert response.ok, response.text
        try:
            assert self.transit_key_length in (16, 24, 32)
        except AssertionError:
            raise ValueError(
                "'transit_key_length'\n\tTransit key length (AES) must be one of 16, 24, or 32 bytes."
            )
        try:
            assert 30 <= self.transit_time_bucket <= 300
        except AssertionError:
            raise ValueError(
                "'transit_time_bucket'\n\tValue must be between 30 and 300 seconds"
            )
        key_length = len(self.vault_apikey)
        try:
            assert key_length >= 32
        except AssertionError:
            raise ValueError(
                f"'vault_apikey'\n\tValue must be at least 32 characters, received {key_length}"
            )
        Fernet(self.vault_secret)


def getenv(*args, default: str = None) -> str:
    """Returns the key-ed environment variable or the default value."""
    for key in args:
        if value := os.environ.get(key.upper()) or os.environ.get(key.lower()):
            return value
    return default


def resolve_secrets(try_aws: bool):
    """Tries to retrieve the required secret from environment variable or AWS parameter or the AWS secrets manager."""
    base_env_vars = dict(
        vault_server=getenv("vault_server", "server"),
        vault_apikey=getenv("vault_apikey", "apikey"),
        vault_secret=getenv("vault_secret", "secret"),
        vault_transit_time_bucket=getenv(
            "vault_transit_time_bucket", "transit_time_bucket", default="60"
        ),
        vault_transit_key_length=getenv(
            "vault_transit_key_length", "transit_time_bucket", default="32"
        ),
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
    raise VaultAPIClientError(
        f"Not all required values were satisfied. Following fields are missing: {unsatisfied}"
    )
