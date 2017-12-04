"""
V1 Client
"""

from threatstack.base import BaseClient

from threatstack.v1 import resources


class Client(BaseClient):

    BASE_URL = "https://app.threatstack.com/api/v1/"

    def __init__(self, api_key=None, org_id=None, user_id=None, timeout=None):
        BaseClient.__init__(self, api_key=api_key, timeout=timeout)
        self.org_id = org_id
        self.user_id = user_id
        self.agents = resources.Agents(self)
        self.alerts = resources.Alerts(self)
        self.logs = resources.Logs(self)
        self.organizations = resources.Organizations(self)
        self.policies = resources.Policies(self)
    
    def request_headers(self, _method, _url):
        headers = { "Authorization": self.api_key }
        if self.org_id:
            headers["Organization"] = self.org_id
        return headers

