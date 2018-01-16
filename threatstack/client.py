"""
This module is a client for the ThreatStack API.
"""

from threatstack.v1 import client as v1_client
from threatstack.v2 import client as v2_client
from threatstack.errors import ThreatStackClientError

CLIENT_VERSIONS = {
    1: v1_client.Client,
    2: v2_client.Client
}

DEFAULT_VERSION = 2

def ThreatStack(api_key=None, org_id=None, api_version=DEFAULT_VERSION, timeout=120, user_id=None):
    """Factory function to return a client version."""
    try:
        client = CLIENT_VERSIONS[int(api_version)]
    except KeyError:
        raise ThreatStackClientError("Invalid API version. Please specify '1' or '2'.")

    kwargs = {
        'api_key': api_key,
        'org_id': org_id,
        'timeout': timeout
    }

    if int(api_version) > 1:
        kwargs["user_id"] = user_id

    return client(**kwargs)
