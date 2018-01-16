"""
Base Client class for versioned clients.
"""

import json
from mohawk import Sender
from mohawk.exc import HawkFail
from retrying import retry
from requests import Request, Session
from six import reraise
from six.moves.urllib.parse import urljoin
import sys

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

    def _get_auth(self, request_url):
        """Returns the correct Authorization header by API version."""
        # if API v2 use hawk auth.
        if self.API_VERSION > 1:
            credentials = {
                'id': self.user_id,
                'key': self.api_key,
                'algorithm': 'sha256'
            }

            sender = Sender(credentials, request_url, 'GET', always_hash_content=False, ext=self.org_id)
            headers = {"Authorization": sender.request_header}

        else:
            sender = None
            headers = {"Authorization": self.api_key}

        return (sender, headers)

    @retry(**RETRY_OPTS)
    def http_request(self, method, path, data=None, params=None):
        """ Wraps HTTP calls to ThrestStack API """

        s = Session()
        url = urljoin(self.BASE_URL, path)
        headers = {}

        hawk_sender, auth_headers = self._get_auth(url)
        headers.update(auth_headers)

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
            return self.handle_response(resp, hawk_sender)

    def handle_response(self, resp, sender=None):
        # ThreatStack can return various things
        # when it fails to find a resource so trying
        # to give raise a consistent error

        # check for failed authorization...
        if resp.status_code == 401:
            raise errors.ThreatStackClientAuthorizationError(
                "Request authorization failure: {}".format(resp.text or "No reason given")
            )

        # ...Now check the response integrity.
        if sender is not None:
            try:
                sender.accept_response(
                    resp.headers['Server-Authorization'],
                    content=resp.text,
                    content_type=resp.headers['Content-Type']
                )
            except HawkFail as e:
                exc_info = sys.exc_info()
                if sys.version_info >= (3,0,0):
                    raise errors.ThreatStackClientAuthorizationError(e).with_traceback(exc_info[2])
                else:
                    six.reraise(
                        errors.ThreatStackClientAuthorizationError,
                        errors.ThreatStackClientAuthorizationError(e),
                        exc_info[2]
                    )

        # Have checked authorization, now let's check responses.
        if resp.status_code >= 500:
            try:
                c = resp.json()
                if c.get("status") is not None:
                    if c["status"].lower() == "error":
                        error = c["message"]
                else:
                    error = "API did not give reason for error"
                raise errors.ThreatStackAPIError(error)
            except json.decoder.JSONDecodeError as e:
                raise errors.ThreatStackAPIError("Threat Stack API returned: {}".format(resp.body))


        elif resp.status_code == 404:
            return {}

        if resp.status_code <= 202:
            if not resp.json():
                return {}
            return resp.json()
