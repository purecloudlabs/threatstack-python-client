"""
This module is a client for the ThreatStack API.
"""

from .v1 import client as v1_client
from .v2 import client as v2_client

CLIENT_VERSIONS = {
    1: v1_client.Client,
    2: v2_client.Client
}

API_VERSION = 2
API_VERSIONS = ["1", "2"]
TIMEOUT = 120 # default http timeout


def ThreatStack(api_version=API_VERSION, api_key=None, org_id=None, timeout=TIMEOUT):
    """Factory function to return a client version."""
    try:
        client = CLIENT_VERSIONS[int(api_version)]
    except KeyError:
        raise Exception("Invalid API version. Please specify '1' or '2'.")

    return client(api_key=api_key, org_id=org_id, timeout=timeout)
