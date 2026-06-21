import hashlib
import hmac
import time
from typing import Any, Callable, Dict, NoReturn

import requests

from vaultapi_client.config import EndpointMapping, EnvConfig
from vaultapi_client.exceptions import VaultAPIServerError
from vaultapi_client.util import urljoin


def _request_error(error: requests.RequestException) -> NoReturn:
    """Uses requests module base exception to raise a custom server error."""
    raise VaultAPIServerError(
        f"Request failed: {error}",
        status_code=getattr(error.response, "status_code", None),
    )


def generate_bearer_token(token: str) -> str:
    """Generate an authentication header value for API requests.

    Args:
        token: Shared API token used as the HMAC secret key.

    See Also:
        - The generated header contains:
            - A Unix timestamp in seconds.
            - An HMAC-SHA512 signature computed using the API token as the secret key and the timestamp as the message.
        - | The server can validate the signature and ensure the timestamp is within an acceptable age window,
          | to reduce replay attacks.

    Example:
        Authorization: Signature=<signature>,timestamp=<timestamp>

    Returns:
        str:
        Authentication header value containing the signature and timestamp.
    """
    timestamp = str(int(time.time()))
    signature = hmac.new(
        token.encode("utf-8"),
        timestamp.encode("utf-8"),
        hashlib.sha512,
    ).hexdigest()
    return f"Signature={signature},timestamp={timestamp}"


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


class Session:
    """Custom requests session with centralized error handling, headers infusion, and response processing.

    >>> Session

    """

    def __init__(self, env_config: EnvConfig) -> None:
        self.apikey = env_config.vault_apikey
        self.secret = env_config.vault_secret
        self.server = env_config.vault_server
        self.headers: Callable = lambda token: {
            "Accept": "application/json",
            "Authorization": f"Bearer {generate_bearer_token(token)}",
        }

    def request(
        self,
        method: str,
        endpoint: EndpointMapping,
        params: Dict[str, Any] | None = None,
        json: Dict[str, Any] | None = None,
    ) -> Any:
        """Intercepts all HTTP requests and applies centralized error handling.

        Args:
            method: HTTP method to make a request.
            endpoint: Endpoint to make a request.
            params: Query parameters to pass to the request.
            json: JSON data to pass to the request.

        Returns:
            Any:
            Response data from the server.
        """
        url = urljoin(self.server, endpoint)
        if method in ("GET", "POST"):
            headers = self.headers(token=self.apikey)
        else:
            headers = self.headers(token=f"{self.apikey}.{self.secret}")
        try:
            response = requests.request(
                method=method, url=url, headers=headers, params=params, json=json
            )
            response.raise_for_status()
            return process_response(response)
        except requests.exceptions.RequestException as error:
            _request_error(error)

    def get(
        self,
        endpoint: EndpointMapping,
        params: Dict[str, Any] | None = None,
        json: Dict[str, Any] | None = None,
    ) -> Any:
        """Make GET request to the server and process the response."""
        return self.request("GET", endpoint, params=params, json=json)

    def put(
        self,
        endpoint: EndpointMapping,
        params: Dict[str, Any] | None = None,
        json: Dict[str, Any] | None = None,
    ) -> Any:
        """Make PUT request to the server and process the response."""
        return self.request("PUT", endpoint, params=params, json=json)

    def post(
        self,
        endpoint: EndpointMapping,
        params: Dict[str, Any] | None = None,
        json: Dict[str, Any] | None = None,
    ) -> Any:
        """Make POST request to the server and process the response."""
        return self.request("POST", endpoint, params=params, json=json)

    def delete(
        self,
        endpoint: EndpointMapping,
        params: Dict[str, Any] | None = None,
        json: Dict[str, Any] | None = None,
    ) -> Any:
        """Make DELETE request to the server and process the response."""
        return self.request("DELETE", endpoint, params=params, json=json)
