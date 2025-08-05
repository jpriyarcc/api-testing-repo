
import requests
import logging

log = logging.getLogger(__name__)


class APIClient:
    """
    A reusable API client for handling HTTP requests with built-in logging and error handling.

    This client abstracts common API operations (GET, POST, PUT, DELETE),
    automatically applies headers, validates responses using `raise_for_status()`,
    and distinguishes API errors (HTTP 4xx/5xx) from network/other errors.
    """

    def __init__(self, base_url: str):
        """
        Initialize the APIClient.

        :param base_url: Base URL for all API requests (e.g., 'https://api.example.com').
        """
        self.base_url = base_url.rstrip("/")

    @staticmethod
    def _get_headers(token=None):
        """
        Construct request headers.

        :param token: Optional Bearer token for Authorization header.
        :return: Dictionary of headers.
        """
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    @staticmethod
    def _handle_response(response):
        """
        Validate and handle an API response.

        - Raises HTTPError for 4xx/5xx.
        - Returns parsed JSON for valid responses.
        """
        try:
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as http_err:
            try:
                error_json = response.json()
            except ValueError:
                error_json = response.text
            log.error(f"API Error [{response.status_code}]: {error_json} | Exception: {http_err}")
            raise
        except requests.exceptions.RequestException as req_err:
            log.error(f"Network/Request Error: {req_err}")
            raise

    def post(self, endpoint, json=None, token=None, params=None):
        """
        Send a POST request.

        :param endpoint: API endpoint (e.g., '/users').
        :param json: JSON payload for the request body.
        :param token: Optional Bearer token for Authorization.
        :param params: Optional query parameters for the request.
        """
        url = f"{self.base_url}{endpoint}"
        log.info(f"POST {url} | Payload: {json} | Params: {params}")
        resp = requests.post(url, headers=self._get_headers(token), json=json, params=params)
        self._handle_response(resp)
        return resp

    def get(self, endpoint, params=None, token=None):
        """
        Send a GET request.

        :param endpoint: API endpoint (e.g., '/users').
        :param params: Query parameters for the request.
        :param token: Optional Bearer token for Authorization.

        """
        url = f"{self.base_url}{endpoint}"
        log.info(f"GET {url} | Params: {params}")
        resp = requests.get(url, headers=self._get_headers(token), params=params)
        return self._handle_response(resp)

    def put(self, endpoint, json=None, token=None):
        """
        Send a PUT request.

        :param endpoint: API endpoint (e.g., '/users/{id}').
        :param json: JSON payload for updating resources.
        :param token: Optional Bearer token for Authorization.

        """
        url = f"{self.base_url}{endpoint}"
        log.info(f"PUT {url} | Payload: {json}")
        resp = requests.put(url, headers=self._get_headers(token), json=json)
        return self._handle_response(resp)

    def delete(self, endpoint, token=None):
        """
        Send a DELETE request.

        :param endpoint: API endpoint (e.g., '/users/{id}').
        :param token: Optional Bearer token for Authorization.

        """
        url = f"{self.base_url}{endpoint}"
        log.info(f"DELETE {url}")
        resp = requests.delete(url, headers=self._get_headers(token))
        return self._handle_response(resp)
