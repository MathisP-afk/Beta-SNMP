"""
API module for REST communication with HTTPS support.
"""

from .api_client import HTTPSAPIClient, create_insecure_client

__version__ = "1.0.0"
__all__ = ["HTTPSAPIClient", "create_insecure_client"]
