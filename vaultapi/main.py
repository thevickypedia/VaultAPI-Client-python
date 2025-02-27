import os
from typing import Dict, List

import dotenv

from vaultapi.aws import LOGGER
from vaultapi.config import getenv, resolve_secrets, server_map
from vaultapi.session import Session
from vaultapi.transit import TransitShield
from vaultapi.util import urljoin


class VaultAPIClient:
    """Vault API client object to retrieve secrets from the VaultAPI Server.

    >>> VaultAPIClient

    """

    def __init__(self, aws: bool = getenv("vault_aws", default="0") in ("1", "true")):
        """Instantiates the VaultAPIClient object."""
        self.env_config = resolve_secrets(aws)
        self.transit_shield = TransitShield(self.env_config)
        self.SESSION = Session()
        self.SESSION.headers = {
            "accept": "application/json",
            "Authorization": f"Bearer {self.env_config.vault_apikey}",
        }

    def _get_cipher(self, server_url: str, query_params: Dict[str, str]) -> str:
        """Get ciphertext from the server.

        Args:
            server_url: Server URL to make the request to.
            query_params: Query parameters to send with the request.

        Returns:
            str:
            Returns the ciphertext.
        """
        return self.SESSION.get(
            server_url,
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
        env_vars = dotenv.dotenv_values(dotenv_file)
        return self.update_secret(secrets=env_vars, table_name=table_name)

    def update_secret(self, secrets: Dict[str, str], table_name: str) -> Dict[str, str]:
        """Update or create secrets in the vault.

        Args:
            secrets: Key value pairs with multiple secrets.
            table_name: Table name.

        Returns:
            Dict[str, str]:
            Returns the server response.
        """
        url = urljoin(self.env_config.vault_server, server_map.put_secret)
        return self.SESSION.put(
            url,
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
        url = urljoin(self.env_config.vault_server, server_map.delete_secret)
        return self.SESSION.delete(
            url,
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
        url = urljoin(self.env_config.vault_server, server_map.list_tables)
        return self.SESSION.get(url)

    def create_table(self, table_name: str) -> Dict[str, str]:
        """Creates a new table in the vault.

        Args:
            table_name: Table name.

        Returns:
            Dict[str, str]:
            Returns the server response.
        """
        url = urljoin(self.env_config.vault_server, server_map.create_table)
        return self.SESSION.post(url, params={"table_name": table_name})

    def delete_table(self, table_name: str) -> Dict[str, str]:
        """Deletes an existing table.

        Args:
            table_name: Table name.

        Returns:
            Dict[str, str]:
            Returns the server response.
        """
        url = urljoin(self.env_config.vault_server, server_map.delete_table)
        return self.SESSION.delete(url, params={"table_name": table_name})

    def get_secret(self, key: str, table_name: str) -> Dict[str, str]:
        """Retrieves multiple secrets from a table.

        Args:
            key: Comma separated list of secret names to be retrieved.
            table_name: Table name.

        Returns:
            Dict[str, str]:
            Returns a dictionary of decrypted values.
        """
        url = urljoin(self.env_config.vault_server, server_map.get_secret)
        cipher_text = self._get_cipher(url, {"key": key, "table_name": table_name})
        return self.transit_shield.decrypt(cipher_text)

    def get_table(self, table_name: str) -> Dict[str, str]:
        """Retrieves all the secrets stored in a table.

        Args:
            table_name: Table name.

        Returns:
            Dict[str, str]:
            Returns a dictionary of decrypted values.
        """
        url = urljoin(self.env_config.vault_server, server_map.get_table)
        cipher_text = self._get_cipher(url, {"table_name": table_name})
        return self.transit_shield.decrypt(cipher_text)

    def decrypt(
        self,
        table: str,
        get_secret: str = None,
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
            LOGGER.warning("No table_name was given")
            return {}
        params = dict(table_name=table)
        if get_secret:
            url = urljoin(self.env_config.vault_server, server_map.get_secret)
            params["key"] = get_secret
        else:
            url = urljoin(self.env_config.vault_server, server_map.get_table)
        return self.transit_shield.decrypt(self._get_cipher(url, params))
