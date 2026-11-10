"""HTTP client for Ghidra HATEOAS API."""

import json
import time
from typing import Any, Dict, Optional
from urllib.parse import quote, urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .exceptions import GhidraAPIError, GhidraConnectionError
from .models import GhidraInstance


class GhidraHTTPClient:
    """HTTP client for communicating with Ghidra plugin API.

    This client handles all HTTP communication with the Ghidra HATEOAS REST API,
    including connection pooling, retries, and error handling.

    Attributes:
        host: Hostname or IP address of Ghidra instance
        port: Port number of Ghidra instance
        timeout: Request timeout in seconds
        base_url: Full base URL for API requests
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8192,
        timeout: int = 900,
        session: Optional[requests.Session] = None,
        dry_run: bool = False
    ):
        """Initialize HTTP client.

        Args:
            host: Hostname or IP address (default: localhost)
            port: Port number (default: 8192)
            timeout: Request timeout in seconds (default: 900)
            session: Session to reuse. A port scan creates one client per
                port; sharing one session keeps the connection pool (and the
                retry adapter) instead of building a new one per port.
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.base_url = f"http://{host}:{port}"
        # --dry-run: a mutation is described, never sent (I12).
        self.dry_run = bool(dry_run)

        # Configure session with retry logic
        if session is None:
            self.session = requests.Session()
            retry_strategy = Retry(
                total=3,
                backoff_factor=0.5,
                status_forcelist=[502, 503, 504],
                allowed_methods=["GET", "POST", "PATCH", "PUT", "DELETE"]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
        else:
            self.session = session


    def _dry_run(self, method: str, endpoint: str,
                 payload: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Describe a mutation instead of sending it, when --dry-run is on.

        The preview is the exact request that would go out. It is deliberately
        client-side: the server never sees it, so a dry run cannot change
        anything even if the server were to disagree about the method.
        """
        if not self.dry_run:
            return None
        plan = f"Dry run: would {method} {endpoint}"
        if payload:
            body = json.dumps(payload, ensure_ascii=False, sort_keys=True)
            if len(body) > 400:
                body = body[:400] + "..."
            plan += f" with {body}"
        return {"success": True, "dry_run": True, "result": plan}

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make GET request to API.

        Args:
            endpoint: API endpoint path (without leading slash)
            params: Optional query parameters

        Returns:
            Parsed JSON response data

        Raises:
            GhidraConnectionError: If connection fails
            GhidraAPIError: If API returns error response
        """
        url = urljoin(self.base_url + "/", endpoint.lstrip("/"))
        headers = {
            "Accept": "application/json",
            "X-Request-ID": f"cli-{int(time.time() * 1000)}"
        }

        try:
            response = self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=self.timeout
            )
            return self._handle_response(response)
        except requests.exceptions.Timeout as e:
            raise GhidraConnectionError(f"Request timed out after {self.timeout}s") from e
        except requests.exceptions.ConnectionError as e:
            raise GhidraConnectionError(
                f"Failed to connect to {self.base_url}. "
                f"Is Ghidra running with the GhydraMCP plugin loaded?"
            ) from e
        except requests.exceptions.RequestException as e:
            raise GhidraConnectionError(f"Request failed: {e}") from e

    def post(
        self,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make POST request to API.

        Args:
            endpoint: API endpoint path
            data: Optional form data
            json_data: Optional JSON payload
            params: Optional query string (the BSim routes take their arguments
                there, including the ones that change state)

        Returns:
            Parsed JSON response data

        Raises:
            GhidraConnectionError: If connection fails
            GhidraAPIError: If API returns error response
        """
        url = urljoin(self.base_url + "/", endpoint.lstrip("/"))
        headers = {
            "Accept": "application/json",
            "X-Request-ID": f"cli-{int(time.time() * 1000)}"
        }

        planned = self._dry_run("POST", endpoint, json_data if json_data is not None else data)
        if planned is not None:
            return planned
        try:
            response = self.session.post(
                url,
                params=params,
                data=data,
                json=json_data,
                headers=headers,
                timeout=self.timeout
            )
            return self._handle_response(response)
        except requests.exceptions.Timeout as e:
            raise GhidraConnectionError(f"Request timed out after {self.timeout}s") from e
        except requests.exceptions.ConnectionError as e:
            raise GhidraConnectionError(
                f"Failed to connect to {self.base_url}"
            ) from e
        except requests.exceptions.RequestException as e:
            raise GhidraConnectionError(f"Request failed: {e}") from e

    def patch(
        self,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make PATCH request to API.

        Args:
            endpoint: API endpoint path
            data: Optional JSON payload
            params: Optional query string

        Returns:
            Parsed JSON response data

        Raises:
            GhidraConnectionError: If connection fails
            GhidraAPIError: If API returns error response
        """
        url = urljoin(self.base_url + "/", endpoint.lstrip("/"))
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Request-ID": f"cli-{int(time.time() * 1000)}"
        }

        planned = self._dry_run("PATCH", endpoint, data)
        if planned is not None:
            return planned
        try:
            response = self.session.patch(
                url,
                params=params,
                json=data,
                headers=headers,
                timeout=self.timeout
            )
            return self._handle_response(response)
        except requests.exceptions.Timeout as e:
            raise GhidraConnectionError(f"Request timed out after {self.timeout}s") from e
        except requests.exceptions.ConnectionError as e:
            raise GhidraConnectionError(
                f"Failed to connect to {self.base_url}"
            ) from e
        except requests.exceptions.RequestException as e:
            raise GhidraConnectionError(f"Request failed: {e}") from e

    def put(
        self,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make PUT request to API.

        Args:
            endpoint: API endpoint path
            data: Optional JSON payload
            params: Optional query string

        Returns:
            Parsed JSON response data

        Raises:
            GhidraConnectionError: If connection fails
            GhidraAPIError: If API returns error response
        """
        url = urljoin(self.base_url + "/", endpoint.lstrip("/"))
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Request-ID": f"cli-{int(time.time() * 1000)}"
        }

        planned = self._dry_run("PUT", endpoint, data)
        if planned is not None:
            return planned
        try:
            response = self.session.put(
                url,
                params=params,
                json=data,
                headers=headers,
                timeout=self.timeout
            )
            return self._handle_response(response)
        except requests.exceptions.Timeout as e:
            raise GhidraConnectionError(f"Request timed out after {self.timeout}s") from e
        except requests.exceptions.ConnectionError as e:
            raise GhidraConnectionError(
                f"Failed to connect to {self.base_url}"
            ) from e
        except requests.exceptions.RequestException as e:
            raise GhidraConnectionError(f"Request failed: {e}") from e

    def delete(self, endpoint: str,
               params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make DELETE request to API.

        Args:
            endpoint: API endpoint path
            params: Optional query string

        Returns:
            Parsed JSON response data

        Raises:
            GhidraConnectionError: If connection fails
            GhidraAPIError: If API returns error response
        """
        url = urljoin(self.base_url + "/", endpoint.lstrip("/"))
        headers = {
            "Accept": "application/json",
            "X-Request-ID": f"cli-{int(time.time() * 1000)}"
        }

        planned = self._dry_run("DELETE", endpoint, None)
        if planned is not None:
            return planned
        try:
            response = self.session.delete(
                url,
                params=params,
                headers=headers,
                timeout=self.timeout
            )
            return self._handle_response(response)
        except requests.exceptions.Timeout as e:
            raise GhidraConnectionError(f"Request timed out after {self.timeout}s") from e
        except requests.exceptions.ConnectionError as e:
            raise GhidraConnectionError(
                f"Failed to connect to {self.base_url}"
            ) from e
        except requests.exceptions.RequestException as e:
            raise GhidraConnectionError(f"Request failed: {e}") from e

    def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """Parse and validate HTTP response.

        Args:
            response: HTTP response object

        Returns:
            Parsed JSON data

        Raises:
            GhidraAPIError: If response indicates error
            GhidraConnectionError: If response is invalid
        """
        # Handle non-OK HTTP status
        if response.status_code >= 400:
            try:
                error_data = response.json()
                if isinstance(error_data, dict):
                    error = error_data.get("error", {})
                    if isinstance(error, dict):
                        raise GhidraAPIError(
                            error.get("message", "Unknown error"),
                            error.get("code", "HTTP_ERROR")
                        )
                    raise GhidraAPIError(str(error), "HTTP_ERROR")
            except requests.exceptions.JSONDecodeError:
                pass
            raise GhidraAPIError(
                f"HTTP {response.status_code}: {response.text[:200]}",
                f"HTTP_{response.status_code}"
            )

        # Parse JSON response
        try:
            data = response.json()
        except requests.exceptions.JSONDecodeError as e:
            raise GhidraConnectionError(
                f"Invalid JSON response: {response.text[:200]}"
            ) from e

        # Validate response structure
        if not isinstance(data, dict):
            raise GhidraAPIError("Invalid response format: expected JSON object", "INVALID_FORMAT")

        # Check for API-level errors
        if not data.get("success", False):
            error = data.get("error", {})
            if isinstance(error, dict):
                raise GhidraAPIError(
                    error.get("message", "Unknown error"),
                    error.get("code", "UNKNOWN")
                )
            raise GhidraAPIError(str(error), "UNKNOWN")

        return data

    def close(self):
        """Close the HTTP session."""
        self.session.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
