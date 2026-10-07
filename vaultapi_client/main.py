import os
from typing import Dict, List

import dotenv

from vaultapi_client.config import EndpointMapping, getenv, resolve_secrets
from vaultapi_client.session import Session
from vaultapi_client.transit import TransitShield


class VaultAPIClient:
    """Vault API client object to retrieve secrets from the VaultAPI Server.

    >>> VaultAPIClient

    """

    def __init__(
        self,
        aws: bool = getenv("vault_aws", default="0") in ("1", "true"),
        vault_server: str | None = None,
        vault_apikey: str | None = None,
        vault_secret: str | None = None,
        vault_transit_time_bucket: int | None = None,
        vault_transit_key_length: int | None = None,
    ):
        """Instantiates the VaultAPIClient object."""
        self.env_config = resolve_secrets(
            aws=aws,
            vault_server=vault_server,
            vault_apikey=vault_apikey,
            vault_secret=vault_secret,
            vault_transit_time_bucket=vault_transit_time_bucket,
            vault_transit_key_length=vault_transit_key_length,
        )
        self.transit_shield = TransitShield(self.env_config)
        self.SESSION = Session(self.env_config)

    def _get_cipher(
        self, endpoint: EndpointMapping, query_params: Dict[str, str]
    ) -> str:
        """Get ciphertext from the server.

        Args:
            endpoint: API endpoint to request.
            query_params: Query parameters to send with the request.

        Returns:
            str:
            Returns the ciphertext.
        """
        return self.SESSION.get(
            endpoint,
            params=query_params,
        )

    def dotenv_to_table(self, table_name: str, dotenv_file: str) -> Dict[str, str]:
        """Store all the env vars from a .env file into the database.

        Args:
            table_name: Name of the table to store secrets.
            dotenv_file: Dot env filename.
        """
        try:
            assert os.path.isfile(dotenv_file)
        except AssertionError:
            raise FileNotFoundError(dotenv_file)
        env_vars = {
            k: v for k, v in dotenv.dotenv_values(dotenv_file).items() if v is not None
        }
        return self.update_secret(secrets=env_vars, table_name=table_name)

    def table_to_env(self, table_name: str, dotenv_file: str | None = None) -> None:
        """Retrieve all secrets from the database and store them as env vars.

        Args:
            table_name: Vault table name,
            dotenv_file: Dot env filename to store secrets in addition to env vars.
        """
        if dotenv_file:
            try:
                assert os.path.isfile(dotenv_file)
            except AssertionError:
                raise FileNotFoundError(dotenv_file)
        secrets = self.get_table(table_name)
        for key, value in secrets.items():
            os.environ[key] = value
            if dotenv_file:
                dotenv.set_key(
                    dotenv_path=dotenv_file, key_to_set=key, value_to_set=value
                )

    def update_secret(self, secrets: Dict[str, str], table_name: str) -> Dict[str, str]:
        """Update or create secrets in the vault.

        Args:
            secrets: Key value pairs with multiple secrets.
            table_name: Table name.

        Returns:
            Dict[str, str]:
            Returns the server response.
        """
        return self.SESSION.put(
            EndpointMapping.put_secret,
            json={
                "secrets": self.transit_shield.encrypt(payload=secrets),
                "table_name": table_name,
            },
        )

    def delete_secret(self, key: str, table_name: str) -> Dict[str, str]:
        """Delete a secret from the vault.

        Args:
            key: Key for the secret.
            table_name: Table name.

        Returns:
            Dict[str, str]:
            Returns the server response.
        """
        return self.SESSION.delete(
            EndpointMapping.delete_secret,
            json={
                "key": key,
                "table_name": table_name,
            },
        )

    def list_tables(self) -> List[str]:
        """List all available tables.

        Returns:
            List[str]:
            Returns the available table names as a list of strings.
        """
        return self.SESSION.get(EndpointMapping.list_tables)

    def create_table(self, table_name: str) -> Dict[str, str]:
        """Creates a new table in the vault database.

        Args:
            table_name: Table name.

        Returns:
            Dict[str, str]:
            Returns the server response.
        """
        return self.SESSION.post(
            EndpointMapping.create_table, params={"table_name": table_name}
        )

    def rename_table(self, table_name: str, new_name: str) -> str:
        """Renames a table in the vault database.

        Args:
            table_name: Table name to rename.
            new_name: New table name.

        Returns:
            str:
            Returns the server response.
        """
        return self.SESSION.patch(
            EndpointMapping.rename_table,
            params={"table_name": table_name},
            json=dict(new_name=new_name),
        )

    def delete_table(self, table_name: str) -> Dict[str, str]:
        """Deletes an existing table.

        Args:
            table_name: Table name.

        Returns:
            Dict[str, str]:
            Returns the server response.
        """
        return self.SESSION.delete(
            EndpointMapping.delete_table, params={"table_name": table_name}
        )

    def get_secret(self, key: str, table_name: str) -> Dict[str, str]:
        """Retrieves multiple secrets from a table.

        Args:
            key: Comma separated list of secret names to be retrieved.
            table_name: Table name.

        Returns:
            Dict[str, str]:
            Returns a dictionary of decrypted values.
        """
        cipher_text = self._get_cipher(
            EndpointMapping.get_secret, {"key": key, "table_name": table_name}
        )
        return self.transit_shield.decrypt(ciphertext=cipher_text)

    def get_table(self, table_name: str) -> Dict[str, str]:
        """Retrieves all the secrets stored in a table.

        Args:
            table_name: Table name.

        Returns:
            Dict[str, str]:
            Returns a dictionary of decrypted values.
        """
        cipher_text = self._get_cipher(
            EndpointMapping.get_table, {"table_name": table_name}
        )
        return self.transit_shield.decrypt(ciphertext=cipher_text)

    def decrypt(
        self,
        table: str,
        get_secret: str | None = None,
    ) -> Dict[str, str] | str:
        """Decrypt function.

        Args:
            table: Table name to retrieve.
            get_secret: Comma separated list of secret keys to retrieve.

        Returns:
            Dict[str, str]:
            Returns a dictionary of decrypted values.
        """
        if not table:
            raise ValueError("Table name is required to decrypt.")
        params = dict(table_name=table)
        if get_secret:
            endpoint = EndpointMapping.get_secret
            params["key"] = get_secret
        else:
            endpoint = EndpointMapping.get_table
        return self.transit_shield.decrypt(
            self._get_cipher(endpoint=EndpointMapping(endpoint), query_params=params)
        )
