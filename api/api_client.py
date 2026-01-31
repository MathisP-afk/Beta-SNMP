"""
HTTPS API client for communicating with REST APIs.
Supports insecure mode for self-signed certificates (testing environment).
Supports API key authentication via headers (Bearer token or custom headers).
"""

import requests
import json
import logging
from typing import Optional, Dict, Any, List
from urllib3.exceptions import InsecureRequestWarning
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# Suppress SSL warnings when using insecure mode
urllib3_logger = logging.getLogger('urllib3.connectionpool')
urllib3_logger.setLevel(logging.ERROR)

# Setup logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)


class HTTPSAPIClient:
    """
    HTTPS API client with support for:
    - Standard HTTPS with certificate verification
    - Insecure mode with disabled SSL verification (for testing)
    - Bearer token authentication (Authorization: Bearer <token>)
    - API key authentication via custom headers
    - Automatic retry on connection failures
    - Session persistence
    
    IMPORTANT: Insecure mode (verify=False) should ONLY be used in:
    - Development/testing environments
    - Internal networks with self-signed certificates
    - Temporary debugging scenarios
    
    Production environments MUST use proper certificate management.
    """
    
    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        auth_type: str = "bearer",  # "bearer", "api_key", or custom header name
        insecure: bool = False,
        verify_ssl: bool = True,
        timeout: int = 10,
        max_retries: int = 3,
        backoff_factor: float = 0.3,
        custom_headers: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize HTTPS API client.
        
        Args:
            base_url: Base URL of the API (e.g., "https://api.example.com")
            api_key: Optional API key for authentication
            auth_type: Type of authentication - "bearer" (default) or header name
            insecure: If True, disable SSL certificate verification (TESTING ONLY!)
            verify_ssl: If True, verify SSL certificates (ignored if insecure=True)
            timeout: Request timeout in seconds
            max_retries: Number of retry attempts
            backoff_factor: Backoff factor for retries
            custom_headers: Additional custom headers to add to all requests
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.insecure = insecure
        
        # Setup session with retry strategy
        self.session = requests.Session()
        
        # Configure retries - compatible with urllib3 2.x
        try:
            # Try urllib3 2.x+ syntax first
            retry_strategy = Retry(
                total=max_retries,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
                backoff_factor=backoff_factor,
            )
        except TypeError:
            # Fallback to urllib3 1.x syntax
            retry_strategy = Retry(
                total=max_retries,
                status_forcelist=[429, 500, 502, 503, 504],
                method_whitelist=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
                backoff_factor=backoff_factor,
            )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        
        # Setup SSL verification
        if self.insecure:
            # Disable SSL verification for testing
            self.session.verify = False
            # Suppress warnings about insecure requests
            urllib3_logger.disabled = True
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            logger.warning(
                "⚠️  SSL VERIFICATION DISABLED - Insecure mode active! "
                "This should ONLY be used in testing/development environments!"
            )
        else:
            # Use standard SSL verification
            self.session.verify = verify_ssl
            logger.info("✓ SSL certificate verification enabled")
        
        # Default headers
        self.session.headers.update({
            'User-Agent': 'Beta-SNMP/1.0',
            'Accept': 'application/json',
        })
        
        # Add API key if provided
        if api_key:
            if auth_type.lower() == "bearer":
                # Standard Bearer token (Authorization: Bearer <token>)
                self.session.headers.update({
                    'Authorization': f'Bearer {api_key}'
                })
                logger.info("✓ Bearer token authentication configured")
            else:
                # Custom header (default X-API-Key)
                header_name = auth_type if auth_type != "api_key" else "X-API-Key"
                self.session.headers.update({
                    header_name: api_key
                })
                logger.info(f"✓ API key authentication configured ({header_name})")
        
        # Add custom headers if provided
        if custom_headers:
            self.session.headers.update(custom_headers)
            logger.info(f"✓ Added {len(custom_headers)} custom header(s)")
        
        logger.info(f"API Client initialized: {self.base_url}")
    
    def _build_url(self, endpoint: str) -> str:
        """
        Build full URL from endpoint.
        
        Args:
            endpoint: API endpoint (e.g., "/api/devices")
            
        Returns:
            Full URL
        """
        endpoint = endpoint.lstrip('/')
        return f"{self.base_url}/{endpoint}"
    
    def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> Optional[Dict[str, Any]]:
        """
        Make HTTP request with error handling.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            endpoint: API endpoint
            **kwargs: Additional arguments for requests library
            
        Returns:
            Response JSON or None if error
        """
        url = self._build_url(endpoint)
        
        try:
            logger.debug(f"{method} {url}")
            
            response = self.session.request(
                method,
                url,
                timeout=self.timeout,
                **kwargs
            )
            
            # Log response
            logger.debug(f"Response: {response.status_code}")
            
            # Check for errors
            if response.status_code >= 400:
                logger.error(
                    f"{method} {endpoint} failed: "
                    f"{response.status_code} - {response.text[:200]}"
                )
                return None
            
            # Try to parse JSON
            if response.text:
                return response.json()
            else:
                return {"status": "success"}
        
        except requests.exceptions.Timeout:
            logger.error(f"Request timeout for {endpoint}")
            return None
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error for {self.base_url}: {e}")
            return None
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON response from {endpoint}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in request: {e}")
            return None
    
    def get(
        self,
        endpoint: str,
        params: Optional[Dict] = None,
        **kwargs
    ) -> Optional[Dict[str, Any]]:
        """
        Make GET request.
        
        Args:
            endpoint: API endpoint
            params: Query parameters
            **kwargs: Additional arguments
            
        Returns:
            Response JSON or None
        """
        return self._request('GET', endpoint, params=params, **kwargs)
    
    def post(
        self,
        endpoint: str,
        data: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        **kwargs
    ) -> Optional[Dict[str, Any]]:
        """
        Make POST request.
        
        Args:
            endpoint: API endpoint
            data: Form data
            json_data: JSON data (converted to json parameter)
            **kwargs: Additional arguments
            
        Returns:
            Response JSON or None
        """
        if json_data is not None:
            kwargs['json'] = json_data
        if data is not None:
            kwargs['data'] = data
        
        return self._request('POST', endpoint, **kwargs)
    
    def put(
        self,
        endpoint: str,
        data: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        **kwargs
    ) -> Optional[Dict[str, Any]]:
        """
        Make PUT request.
        
        Args:
            endpoint: API endpoint
            data: Form data
            json_data: JSON data
            **kwargs: Additional arguments
            
        Returns:
            Response JSON or None
        """
        if json_data is not None:
            kwargs['json'] = json_data
        if data is not None:
            kwargs['data'] = data
        
        return self._request('PUT', endpoint, **kwargs)
    
    def delete(
        self,
        endpoint: str,
        **kwargs
    ) -> Optional[Dict[str, Any]]:
        """
        Make DELETE request.
        
        Args:
            endpoint: API endpoint
            **kwargs: Additional arguments
            
        Returns:
            Response JSON or None
        """
        return self._request('DELETE', endpoint, **kwargs)
    
    def patch(
        self,
        endpoint: str,
        data: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        **kwargs
    ) -> Optional[Dict[str, Any]]:
        """
        Make PATCH request.
        
        Args:
            endpoint: API endpoint
            data: Form data
            json_data: JSON data
            **kwargs: Additional arguments
            
        Returns:
            Response JSON or None
        """
        if json_data is not None:
            kwargs['json'] = json_data
        if data is not None:
            kwargs['data'] = data
        
        return self._request('PATCH', endpoint, **kwargs)
    
    def upload_file(
        self,
        endpoint: str,
        file_path: str,
        field_name: str = "file",
        **kwargs
    ) -> Optional[Dict[str, Any]]:
        """
        Upload file to API.
        
        Args:
            endpoint: API endpoint
            file_path: Path to file
            field_name: Form field name for file
            **kwargs: Additional arguments
            
        Returns:
            Response JSON or None
        """
        try:
            with open(file_path, 'rb') as f:
                files = {field_name: f}
                return self._request('POST', endpoint, files=files, **kwargs)
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            return None
    
    def health_check(self, endpoint: str = "/health") -> bool:
        """
        Check API health.
        
        Args:
            endpoint: Health check endpoint
            
        Returns:
            True if API is healthy
        """
        response = self.get(endpoint)
        return response is not None
    
    def close(self) -> None:
        """
        Close the session and cleanup.
        """
        self.session.close()
        logger.info("API session closed")


# Helper function for creating insecure client (testing only)
def create_insecure_client(
    base_url: str,
    api_key: Optional[str] = None,
    auth_type: str = "bearer",
    **kwargs
) -> HTTPSAPIClient:
    """
    Create API client with SSL verification disabled (TESTING ONLY).
    
    Use this ONLY for:
    - Development environments
    - Testing with self-signed certificates
    - Temporary debugging
    
    Production environments MUST use proper certificates!
    """
    logger.warning(
        "\n" +
        "="*60 +
        "\n⚠️  INSECURE MODE - SSL VERIFICATION DISABLED" +
        "\n" +
        "This client is configured for testing/development ONLY!" +
        "\nNever use in production or with sensitive data!" +
        "\n" +
        "="*60 + "\n"
    )
    return HTTPSAPIClient(
        base_url,
        api_key=api_key,
        auth_type=auth_type,
        insecure=True,
        **kwargs
    )


if __name__ == "__main__":
    # Example usage - TESTING ONLY
    import os
    
    # Example with insecure mode (self-signed certificate) + Bearer token
    api_key = "vp1p-s8_iq-W08ZR5Wt9U6PYvwVGmWjwbzTLE4NsT1RoiY6bJzgFgfhrzcCkmRl_"
    api_client = create_insecure_client(
        "http://192.168.1.15:8000",
        api_key=api_key,
        auth_type="bearer",
        timeout=10,
        max_retries=3
    )
    
    # Example GET request
    # result = api_client.get("/snmp/list")
    # print("Packets:", result)
    
    api_client.close()
