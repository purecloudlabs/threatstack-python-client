"""
v2 Client
"""
from mohawk import Sender

from threatstack.errors import ThreatStackClientError
from threatstack.base import BaseClient
from threatstack import errors

from threatstack.v2 import resources

class Client(BaseClient):
    BASE_URL = 'https://api.threatstack.com/v2/'

    def __init__(self, api_key=None, org_id=None, user_id=None, timeout=None):
        BaseClient.__init__(self, api_key=api_key, timeout=timeout)
        self.org_id = org_id
        self.user_id = user_id
        self.agents = resources.Agents(self)
        self.alerts = resources.Alerts(self)
        self.vulnerabilities= resources.Vulnerabilities(self)
        self.rulesets = resources.Rulesets(self)
        self.ec2servers = resources.Ec2Servers(self)

    @property
    def org_id(self):
        return self._org_id

    @org_id.setter
    def org_id(self, k):
        if not k:
            raise ThreatStackClientError("org_id is required.")
        self._org_id = k

    @property
    def user_id(self):
        return self._user_id

    @user_id.setter
    def user_id(self, k):
        if not k:
            raise ThreatStackClientError("user_id is required.")
        self._user_id = k

    def request_headers(self, method, url):
        credentials = {
            'id': self.user_id,
            'key': self.api_key,
            'algorithm': 'sha256'
        }
        sender = Sender(credentials, url, method, always_hash_content=False, ext=self.org_id)
        return { 'Authorization': sender.request_header }

    def handle_response(self, resp):
        # ThreatStack can return various things
        # when it fails to find a resource so trying
        # to give raise a consistent error
        if resp.status_code >= 500:
            raise errors.ThreatStackAPIError(resp.json())
        elif resp.status_code == 401:
            raise errors.ThreatStackAPIError("Authentication error")
        elif resp.status_code == 404:
            return {}

        if resp.status_code <= 202:
            if not resp.json():
                return {}
            return resp.json()
