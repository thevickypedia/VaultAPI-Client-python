import argparse
import json

from .main import LOGGER, VaultAPIClient, VaultAPIClientError  # noqa: F401

version = "0.0.1"


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
             "Requires 'pip install VaultAPI-Client[aws]'"
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
    vaultapi_client = VaultAPIClient(args.aws)
    kwargs = dict(args._get_kwargs())
    kwargs.pop("version", None)
    kwargs.pop("aws", None)
    print(json.dumps(vaultapi_client.decrypt(**kwargs), indent=2))
