import base64
import hashlib
import json
import secrets
import time
from typing import Any, ByteString, Dict

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vaultapi.config import EnvConfig
from vaultapi.exceptions import InvalidCipherText


class TransitShield:
    """Object to handle transit encryption and decryption.

    >>> TransitShield

    """

    def __init__(self, env_config: EnvConfig):
        """Instantiates the transit shield object."""
        self.env_config = env_config

    def _string_to_aes_key(self, input_string: str) -> ByteString:
        """Hashes the string.

        Args:
            input_string: String for which an AES hash has to be generated.

        See Also:
            AES supports three key lengths:
                - 128 bits (16 bytes)
                - 192 bits (24 bytes)
                - 256 bits (32 bytes)

        Returns:
            str:
            Return the first 16 bytes for the AES key
        """
        hash_object = hashlib.sha256(input_string.encode())
        return hash_object.digest()[: self.env_config.transit_key_length]

    def encrypt(
        self, payload: Dict[str, Any], url_safe: bool = True
    ) -> ByteString | str:
        """Encrypt a message using GCM mode with 12 fresh bytes.

        Args:
            payload: Payload to be encrypted.
            url_safe: Boolean flag to perform base64 encoding to perform JSON serialization.

        Returns:
            ByteString | str:
            Returns the ciphertext as a string or bytes based on the ``url_safe`` flag.
        """
        nonce = secrets.token_bytes(12)
        encoded = json.dumps(payload).encode()
        epoch = int(time.time()) // self.env_config.transit_time_bucket
        aes_key = self._string_to_aes_key(
            f"{epoch}.{self.env_config.vault_apikey}.{self.env_config.vault_secret}"
        )
        ciphertext = nonce + AESGCM(aes_key).encrypt(nonce, encoded, b"")
        if url_safe:
            return base64.b64encode(ciphertext).decode("utf-8")
        return ciphertext

    def decrypt(self, ciphertext: str | ByteString) -> Dict[str, Any]:
        """Decrypt transit encrypted payload.

        Args:
            ciphertext: Ciphertext to decrypt.

        Returns:
            Dict[str, str]:
            Returns a dictionary of decrypted values.
        """
        epoch = int(time.time()) // self.env_config.transit_time_bucket
        serialized = (
            f"{epoch}.{self.env_config.vault_apikey}.{self.env_config.vault_secret}"
        )
        encoded = serialized.encode()
        hash_object = hashlib.sha256(encoded)
        aes_key = hash_object.digest()[: self.env_config.transit_key_length]
        if isinstance(ciphertext, str):
            ciphertext = base64.b64decode(ciphertext)
        try:
            decrypted = AESGCM(aes_key).decrypt(ciphertext[:12], ciphertext[12:], b"")
        except InvalidTag:
            raise InvalidCipherText("Ciphertext has either expired or invalid!")
        return json.loads(decrypted)
