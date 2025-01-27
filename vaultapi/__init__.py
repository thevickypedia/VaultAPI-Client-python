import argparse
import json

from .exceptions import VaultAPIClientError
from .main import LOGGER, VaultAPIClient

version = "0.1.2"


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
        "--get-secret", help="Retrieve a secret from Vault using the secret key"
    )
    parser.add_argument(
        "--get-secrets",
        help="Retrieve multiple secrets from Vault with a comma separated list of keys",
    )
    parser.add_argument(
        "--table",
        help="Table name where the secrets are stored. "
        "Can be used with --get-secret/--get-secrets or itself to retrieve all the secrets in a table",
    )
    args = parser.parse_args()
    if args.version:
        print(f"VaultAPI Client: {version}")
        exit(0)
    try:
        vaultapi_client = VaultAPIClient(args.aws)
    except VaultAPIClientError as error:
        LOGGER.exception(error)
        exit(1)
    kwargs = dict(args._get_kwargs())
    kwargs.pop("version", None)
    kwargs.pop("aws", None)
    LOGGER.debug(kwargs)
    print(json.dumps(vaultapi_client.decrypt(**kwargs), indent=2))
