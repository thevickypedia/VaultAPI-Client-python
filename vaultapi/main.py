from typing import Any, Dict, List

import requests

from vaultapi.aws import LOGGER
from vaultapi.config import getenv, resolve_secrets, server_map
from vaultapi.transit import TransitShield
from vaultapi.util import urljoin


def process_response(response: requests.Response) -> Any:
    """Asserts on the response code, and returns the response detail.

    Args:
        response: Takes the Response object as an argument.
    """
    assert response.ok, response.text
    return response.json()["detail"]


class VaultAPIClient:
    """Vault API client object to retrieve secrets from the VaultAPI Server.

    >>> VaultAPIClient

    """

    def __init__(self, aws: bool = getenv("vault_aws", default="0") in ("1", "true")):
        """Instantiates the VaultAPIClient object."""
        self.env_config = resolve_secrets(aws)
        self.transit_shield = TransitShield(self.env_config)
        self.SESSION = requests.Session()
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
        response = self.SESSION.get(
            server_url,
            params=query_params,
        )
        return process_response(response)

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
        response = self.SESSION.put(
            url,
            json={
                "secrets": self.transit_shield.encrypt(payload=secrets),
                "table_name": table_name,
            },
        )
        return process_response(response)

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
        response = self.SESSION.delete(
            url,
            json={
                "key": key,
                "table_name": table_name,
            },
        )
        return process_response(response)

    def list_tables(self) -> List[str]:
        """List all available tables.

        Returns:
            List[str]:
            Returns the available table names as a list of strings.
        """
        url = urljoin(self.env_config.vault_server, server_map.list_tables)
        response = self.SESSION.get(url)
        return process_response(response)

    def create_table(self, table_name: str) -> Dict[str, str]:
        """Creates a new table in the vault.

        Args:
            table_name: Table name.

        Returns:
            Dict[str, str]:
            Returns the server response.
        """
        url = urljoin(self.env_config.vault_server, server_map.create_table)
        response = self.SESSION.post(url, params={"table_name": table_name})
        return process_response(response)

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
