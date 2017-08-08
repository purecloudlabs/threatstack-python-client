"""
v2 Client
"""

from threatstack.errors import ThreatStackClientError
from threatstack.base import BaseClient

from . import resources

class Client(BaseClient):
    def __init__(self, api_key=None, org_id=None, timeout=None):
        BaseClient.__init__(self, api_version=2, api_key=api_key, timeout=timeout)
        self.org_id = org_id
        self.agents = resources.Agents(self)
        self.org_id_header = "Organization-Id"

    @property
    def org_id(self):
        return self._org_id

    @org_id.setter
    def org_id(self, k):
        if not k:
            raise ThreatStackClientError("org_id is required.")
        self._org_id = k
