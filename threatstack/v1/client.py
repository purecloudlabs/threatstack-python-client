"""
V1 Client
"""

from threatstack.base import BaseClient

from . import resources


class Client(BaseClient):
    def __init__(self, api_key=None, org_id=None, timeout=None):
        BaseClient.__init__(self, api_version=1, api_key=api_key, timeout=timeout)
        self.org_id = org_id
        self.org_id_header = "Organization"
        self.agents = resources.Agents(self)
        self.alerts = resources.Alerts(self)
        self.logs = resources.Logs(self)
        self.organizations = resources.Organizations(self)
        self.policies = resources.Policies(self)

