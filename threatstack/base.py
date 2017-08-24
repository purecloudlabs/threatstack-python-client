"""
Base Client class for versioned clients.
"""

import json
from retrying import retry
from requests import Request, Session
from six.moves.urllib.parse import urljoin

from threatstack import errors


def retry_on_429(exc):
    """ Used to trigger retry on rate limit """
    return isinstance(exc, errors.APIRateLimitError)


class BaseClient(object):
    """ """

    RETRY_OPTS = {
        "wait_exponential_multiplier": 1000,
        "wait_exponential_max": 10000,
        "stop_max_delay": 60000,
        "retry_on_exception": retry_on_429
    }

    def __init__(self, api_key=None, timeout=120):
        self.api_key = api_key
        self.timeout = timeout

    @property
    def api_key(self):
        return self._api_key

    @api_key.setter
    def api_key(self, k):
        if not k:
            raise errors.ThreatStackClientError("api_key is required")
        self._api_key = k

    @retry(**RETRY_OPTS)
    def http_request(self, method, path, data=None, params=None):
        """ Wraps HTTP calls to ThrestStack API """

        s = Session()
        url = urljoin(self.BASE_URL, path)
        headers = {"Authorization": self.api_key}
        if self.org_id:
            headers[self.org_id_header] = self.org_id

        req = Request(
            method,
            url,
            headers=headers,
            data=data,
            params=params
        )
        prepped = req.prepare()
        resp = s.send(prepped, timeout=self.timeout)
        if resp.status_code == 429:
            raise errors.APIRateLimitError("Threat Stack API rate limit exceeded")
        else:
            return self.handle_response(resp)

    def handle_response(self, resp):
        # ThreatStack can return various things
        # when it fails to find a resource so trying
        # to give raise a consistent error
        if resp.status_code >= 500:
            if "status" in resp.json():
                c = resp.json()
                if c["status"].lower() == "error":
                    error = c["message"]
                    raise errors.ThreatStackAPIError(error)

        elif resp.status_code == 404:
            return {}

        if resp.status_code <= 202:
            if not resp.json():
                return {}
            return resp.json()
