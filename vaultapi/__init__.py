import argparse

from .main import decrypt  # noqa: F401

version = "0.0.1a0"


def commandline():
    """Entrypoint for vaultapi commandline."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-V", "--version", action="store_true", help="Show version information"
    )
    parser.add_argument("--decipher", help="Decipher a given ciphertext")
    parser.add_argument("--get-secret", help="Retrieve a secret from Vault using the secret key")
    parser.add_argument(
        "--get-secrets",
        help="Retrieve multiple secrets from Vault with a comma separated list of keys"
    )
    parser.add_argument(
        "--table",
        help="Table name where the secrets are stored. "
             "Can be used with --get-secret/--get-secrets or itself to retrieve all the secrets in a table"
    )
    args = parser.parse_args()
    if args.version:
        print(f"VaultAPI Client: {version}")
        exit(0)
    if args.decipher:
        print(decrypt(cipher=args.decipher))
        exit(0)
    kwargs = dict(args._get_kwargs())
    kwargs.pop("version", None)
    kwargs.pop("decipher", None)
    print(decrypt(**kwargs))
