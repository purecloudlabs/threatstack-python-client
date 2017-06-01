"""
This module is a client for the ThreatStack API.
"""

import json
from retrying import retry
from requests import Request, Session
try:
    from urllib.parse import urljoin # Python 3
except ImportError:
     from urlparse import urljoin # Python 2

from . import resources
from . import errors


def retry_on_429(exc):
    """ Used to trigger retry on rate limit """
    return isinstance(exc, errors.APIRateLimitError)


class ThreatStack(object):
    """ Client for interacting with ThreatStack API """

    API_VERSION = "1"
    BASE_URL = "https://app.threatstack.com/api/v1/"
    TIMEOUT = 120
    RETRY_OPTS = {
        "wait_exponential_multiplier": 1000,
        "wait_exponential_max": 10000,
        "stop_max_delay": 60000,
        "retry_on_exception": retry_on_429
    }

    def __init__(self, api_key=None, org_id=None, api_version=API_VERSION, timeout=TIMEOUT):
        if api_version is not None:
            self.api_version = api_version

        self.api_key = api_key
        self.org_id = org_id
        self.agents = resources.Agents(self)
        self.alerts = resources.Alerts(self)
        self.logs = resources.Logs(self)
        self.organizations = resources.Organizations(self)
        self.policies = resources.Policies(self)

    @property
    def api_key(self):
        return self._api_key

    @api_key.setter
    def api_key(self, k):
        if not k:
            raise errors.ThreatStackClientError("API key not specified")
        self._api_key = k

    @retry(**RETRY_OPTS)
    def http_request(self, method, path, data=None, params=None):
        """ Wraps HTTP calls to ThrestStack API """

        s = Session()
        url = urljoin(self.BASE_URL, path)
        headers = {"Authorization": self.api_key}
        if self.org_id:
            headers["Organization"] = self.org_id

        req = Request(
            method,
            url,
            headers=headers,
            data=data,
            params=params
        )
        prepped = req.prepare()
        resp = s.send(prepped, timeout=self.TIMEOUT)
        if resp.status_code == 429:
            raise errors.APIRateLimitError("Threat Stack API rate limit exceeded")
        else:
            return self.handle_response(resp)


    def handle_response(self, resp):
        # ThreatStack can return various things
        # when it fails to find a resource so trying
        # to give raise a consistent error
        if not resp.json():
            return {}

        if resp.status_code >= 500:
            if "status" in resp.json():
                c = resp.json()
                if c["status"].lower() == "error":
                    error = c["message"]
                    raise errors.ThreatStackAPIError(error)

        if resp.status_code == 404:
            return {}

        if resp.status_code <= 202:
            return resp.json()
