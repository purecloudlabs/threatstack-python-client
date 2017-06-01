"""
ThreatStack Python Client Exceptions
"""


class Error(Exception):
    pass


class ThreatStackClientError(Exception):
    pass


class ThreatStackAPIError(Error):
    pass


class APIRateLimitError(Error):
    """ Used to trigger retry on rate limit """
    pass
