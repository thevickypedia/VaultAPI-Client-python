import argparse
import json

from .exceptions import VaultAPIClientError
from .main import LOGGER, VaultAPIClient

version = "0.2.0"


def commandline():
    """Entrypoint for vaultapi commandline."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-V", "--version", action="store_true", help="Show version information"
    )
    parser.add_argument(
        "--aws",
        action="store_true",
        help="Flag to use AWS parameter store and secrets manager to retrieve the server credentials. "
        "Requires 'pip install VaultAPI-Client[aws]'",
    )
    parser.add_argument(
        "--get-secret",
        help="Retrieve a secret from Vault using the secret key, or leave it empty to get the entire table.",
    )
    parser.add_argument(
        "--table",
        help="Table name where the secrets are stored. Required to retrieve a secret from the Vault API.",
    )
    kwargs = dict(parser.parse_args()._get_kwargs())
    if kwargs["version"]:
        print(f"VaultAPI Client: {version}")
        exit(0)
    assert kwargs["table"] is not None, "table name must be provided"
    try:
        vaultapi_client = VaultAPIClient(kwargs["aws"])
    except VaultAPIClientError as error:
        LOGGER.exception(error)
        exit(1)
    kwargs.pop("version", None)
    kwargs.pop("aws", None)
    LOGGER.debug(kwargs)
    print(json.dumps(vaultapi_client.decrypt(**kwargs), indent=2))
