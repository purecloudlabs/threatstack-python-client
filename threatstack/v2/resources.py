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

    def list(self, key=None, path_extra=None, start=None, end=None, **kwargs):
        """
        This function supports query string filters used by
        the Threat Stack API by accepting arbitrary **kwargs
        and adding them to the requests params argument.  Given
        the variety of query strings among the resources I wanted
        to keep this function generic.

        :param key: used when the resource class name does not match
                    the JSON key in the HTTP response
        :param path_extra: used to append a string to the URI path
        :param start: maps to the `from` parameter for time ranges
        :param end: maps to the `until` parameter for time ranges
        :param kwargs: used to add additional item to querystring

        :return: a generator object to iterate over the results
        """
        if not key:
            key = self.name

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
                token = resp.get("token", None)
                params["token"]  = token
                items = resp[key]
                for i in items:
                    yield i
            else:
                return

class Agents(Resource):
    def list(self, offline=False, **kwargs):
        path_extra = "offline" if offline else None
        return super(Agents, self).list(path_extra=path_extra, **kwargs)


class Alerts(Resource):
    def list(self, dismissed=False, **kwargs):
        path_extra = "dismissed" if dismissed else None
        return super(Alerts, self).list(path_extra=path_extra, **kwargs)

    def severity_counts(self, **kwargs):
        """
        Return a list of the severity counts
        """
        path = "alerts/severity-counts"
        resp = self.client.http_request("GET", path)
        return resp.get("severityCounts", [])

    def event(self, alert_id="", event_id="", **kwargs):
        path = "{}/{}/events/{}".format(self.name, alert_id, event_id)
        resp = self.client.http_request("GET", path)
        return resp


class Vulnerabilities(Resource):
    def list(self, suppressed=False, package=None, server=None, agent=None, **kwargs):
        path_extra = ""
        key = "cves"

        if package:
            key="packages"
            path_extra += "package/{}".format(package)
        elif server:
            path_extra += "server/{}".format(server)
        elif agent:
            path_extra += "agent/{}".format(agent)
        if suppressed:
            if path_extra:
                path_extra += "/suppressed"
            else:
                path_extra += "suppressed"
        return super(Vulnerabilities, self).list(key=key, path_extra=path_extra, **kwargs)


class Rulesets(Resource):
    def rules(self, ruleset_id=None, rule_id=None, **kwargs):
        """Return a single rule if caller specified a rule_id,
        othewise return list of rules for the ruleset."""
        if rule_id:
            path = "rulesets/{}/rules/{}".format(ruleset_id, rule_id)
            resp = self.client.http_request("GET", path)
            return resp
        else:
            path_extra = "{}/rules".format(ruleset_id)
            return super(Rulesets, self).list(key="rules", path_extra=path_extra, **kwargs)


class Servers(Resource):
    def list(self, non_monitored=False, **kwargs):
        path_extra = "non-monitored" if non_monitored else None
        return super(Servers, self).list(path_extra=path_extra, **kwargs)

