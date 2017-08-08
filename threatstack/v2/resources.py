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

    def list(self, page=None, count=None, start=None, end=None, fields=[]):
        params = {}
        if count:
            params["count"] = count
        if start:
            params["start"] = start
        if end:
            params["end"] = end
        if fields:
            params["fields"] = fields

        # if pagination is not supported
        if not self.paginated:
            resp = self.client.http_request("GET", self.name, params=params)
            for item in resp:
                yield item

        # if user wants a specific page
        elif page is not None:
            params["page"] = page
            resp = self.client.http_request("GET", self.name, params=params)
            if resp:
                for item in resp:
                    yield item

        elif self.paginated:
            page = 0
            params["count"] = 100 # minimize api calls
            while True:
                this_page = page
                params["page"] = this_page
                resp = self.client.http_request("GET", self.name, params=params)
                if resp:
                    for i in resp:
                        yield i
                    page += 1
                else:
                    break


class Agents(Resource):
    pass


class Alerts(Resource):
    pass


class Logs(Resource):
    def get(self, *args, **kwargs):
        raise ThreatStackClientError("API method not supported")


class Organizations(Resource):
    paginated = False

    def get(self, *args, **kwargs):
        raise ThreatStackClientError("API method not supported")

    def users(self, id):
        path = "{}/{}/users".format(self.name, id)
        resp = self.client.http_request("GET", path)
        if resp:
            for user in resp:
                yield user


class Policies(Resource):
    paginated = False
