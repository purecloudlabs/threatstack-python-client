"""
Wrappers for the various ThreatStack resources.
"""

from threatstack.errors import ThreatStackClientError


class Resource(object):
    """ Generic wrapper for API resource """
    paginated = True

    def __init__(self, client):
        self.client = client
        self.name = self.__class__.__name__.lower()

    def get(self, id, fields=[]):
        path = "{}/{}".format(self.name, id)
        params = {}
        if fields:
            params["fields"] = fields

        resp = self.client.http_request("GET", path, params=params)
        return resp

    def list(self, path_extra=None, start=None, end=None, token=None, **kwargs):
        """
        This function supports query string filters used by
        the Threat Stack API by accepting arbitrary **kwargs
        and adding them to the requests params argument.  Given
        the variety of query strings among the resources I wanted
        to keep this function generic.
        """
        if path_extra:
            path = "{}/{}".format(self.name, path_extra)
        else:
            path = self.name

        params = {}
        token = True # assume all lists will support pagination

        for k,v in kwargs.items():
            params[k] = v
        if start:
            params["from"] = start
        if end:
            params["until"] = end

        while token:
            resp = self.client.http_request("GET", path, params=params)
            if resp:
                token = resp["token"]
                params["token"]  = token
                items = resp[self.name]
                for i in items:
                    yield i

class Agents(Resource):
    def offline(self, path_extra="offline", **kwargs):
        return super(Agents, self).list(path_extra="offline", **kwargs)


class Alerts(Resource):
    pass
