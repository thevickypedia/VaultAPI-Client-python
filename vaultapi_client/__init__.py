import argparse
import json
import time

from .exceptions import VaultAPIClientError  # noqa: F401
from .main import VaultAPIClient

version = "0.3.4"


def commandline():
    """Entrypoint for vaultapi commandline."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-V", "--version", action="store_true", help="Show version information"
    )
    parser.add_argument(
        "--get-secret",
        help="Retrieve a secret from Vault using the secret key, or leave it empty to get the entire table.",
    )
    parser.add_argument(
        "--table",
        help="Table name where the secrets are stored. Required to retrieve a secret from the Vault API.",
    )
    parser.add_argument(
        "--env",
        help="Writes to a .env file. Set to false to print the output in stdout.",
        type=bool,
        default=False,
    )
    kwargs = dict(parser.parse_args()._get_kwargs())
    if kwargs["version"]:
        print(f"VaultAPI Client: {version}")
        exit(0)
    if not kwargs["table"]:
        raise ValueError("table name must be provided")
    kwargs.pop("version", None)
    env_writer = kwargs.pop("env", False)
    data = VaultAPIClient().decrypt(**kwargs)
    if env_writer:
        filename = f".vault_{int(time.time())}.env"
        with open(filename, "w") as file:
            for key, value in data.items():
                escaped_value = value.replace("'", "'\\''")
                file.write(f"export {key}='{escaped_value}'\n")
            file.flush()
        print(filename)
    else:
        print(json.dumps(data, indent=2))
