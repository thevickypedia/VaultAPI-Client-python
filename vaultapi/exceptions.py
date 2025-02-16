class VaultAPIError(BaseException):
    """Base error class for VaultAPI."""


class VaultAPIClientError(VaultAPIError):
    """Subclass for client error."""


class InvalidCipherText(VaultAPIClientError):
    """Subclass for invalid tag."""


class VaultAPIServerError(VaultAPIClientError):
    """Subclass for errors when connecting to the server."""

    def __init__(self, message: str, status_code: int = None):
        """Super class to handle custom error message and status code."""
        self.message = message
        self.status_code = status_code
        super().__init__(message)
