from typing import Any, NoReturn

import requests

from vaultapi.exceptions import VaultAPIServerError


def _request_error(error: requests.RequestException) -> NoReturn:
    """Uses requests module base exception to raise a custom server error."""
    raise VaultAPIServerError(
        f"Request failed: {error}",
        status_code=getattr(error.response, "status_code", None),
    )


def process_response(response: requests.Response) -> Any:
    """Asserts on the response code, and returns the response detail.

    Args:
        response: Takes the Response object as an argument.
    """
    try:
        response.raise_for_status()
        return response.json()["detail"]
    except requests.RequestException as error:
        _request_error(error)
    except requests.JSONDecodeError as error:
        raise VaultAPIServerError(
            message=f"Invalid JSON response from the server: {error}"
        )


class Session(requests.Session):
    """Custom requests session with centralized error handling.

    >>> Session

    """

    def request(self, method, url, **kwargs) -> Any:
        """Intercepts all HTTP requests and applies centralized error handling."""
        try:
            response = super().request(method, url, **kwargs)
            response.raise_for_status()
            return process_response(response)
        except requests.exceptions.RequestException as error:
            _request_error(error)

    def get(self, url, **kwargs) -> Any:
        """Make GET request to the server and process the response."""
        return self.request("GET", url, **kwargs)

    def put(self, url, **kwargs) -> Any:
        """Make PUT request to the server and process the response."""
        return self.request("PUT", url, **kwargs)

    def post(self, url, **kwargs) -> Any:
        """Make POST request to the server and process the response."""
        return self.request("POST", url, **kwargs)

    def delete(self, url, **kwargs) -> Any:
        """Make DELETE request to the server and process the response."""
        return self.request("DELETE", url, **kwargs)
