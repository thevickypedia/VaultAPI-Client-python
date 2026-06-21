import os
from enum import Enum
from typing import NoReturn

import dotenv
import requests
from cryptography.fernet import Fernet
from packaging import version

from vaultapi_client.aws import AWSClient
from vaultapi_client.exceptions import VaultAPIClientError, VaultAPIServerError
from vaultapi_client.util import urljoin

env_file = os.environ.get("ENV_FILE") or os.environ.get("env_file") or ".env"
dotenv.load_dotenv(env_file)
MINIMUM_SERVER_VERSION = version.parse("0.6.0a0")


class EndpointMapping(Enum):
    """Enum like function to get all endpoint names to avoid hard coding.

    >>> EndpointMapping

    """

    health = "/health"
    version = "/version"
    get_table = "/get-table"
    get_secret = "/get-secret"
    put_secret = "/put-secret"
    list_tables = "/list-tables"
    create_table = "/create-table"
    delete_table = "/delete-table"
    delete_secret = "/delete-secret"


class EnvConfig:
    """Wrapper for env configuration.

    >>> EnvConfig

    """

    def __init__(
        self,
        vault_server: str,
        vault_apikey: str,
        vault_secret: str,
        vault_transit_key_length: int,
        vault_transit_time_bucket: int,
    ) -> None:
        """Instantiates the env config."""
        self.vault_server: str = vault_server
        self.vault_apikey: str = vault_apikey
        self.vault_secret: str = vault_secret
        self.transit_key_length: int = int(vault_transit_key_length)
        self.transit_time_bucket: int = int(vault_transit_time_bucket)
        self.__assert__()

    def server_check(self, endpoint: EndpointMapping) -> None | NoReturn:
        """Checks if the server is reachable and matches the required version.

        Args:
            endpoint: Endpoint to check.
        """
        try:
            response = requests.get(
                url=urljoin(self.vault_server, endpoint), timeout=(1, 1)
            )
            response.raise_for_status()
        except requests.RequestException as error:
            context = (
                error.response.text
                if (error.response and error.response.text)
                else str(error.__context__)
            )
            raise VaultAPIServerError(
                message=context,
                status_code=getattr(error.response, "status_code", None),
            )
        if endpoint == EndpointMapping.version:
            # Make sure server_version is more than MINIMUM_SERVER_VERSION
            server_version = version.parse(response.json())
            if server_version < MINIMUM_SERVER_VERSION:
                raise VaultAPIServerError(
                    f"Server version [{server_version}] is below the minimum required version "
                    f"[{MINIMUM_SERVER_VERSION}]. Please upgrade the server [OR] use the client version <=0.2.0."
                )

    def __assert__(self) -> None | NoReturn:
        """Run assertions for server config."""
        self.server_check(EndpointMapping.health)
        self.server_check(EndpointMapping.version)
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


def resolve_secrets(try_aws: bool) -> EnvConfig | NoReturn:
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
