"""
Wrappers for the various ThreatStack resources.
"""

from threatstack.errors import ThreatStackClientError


class Resource(object):
    """ Generic wrapper for API resource """
    paginated = True
    name = None

    def __init__(self, client):
        self.client = client
        if self.name is None:
            self.name = self.__class__.__name__.lower()

    def get(self, id, fields=None):
        if fields is None:
            fields = []
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
            if v is not None:
                params[k] = v
        if start:
            params["from"] = start
        if end:
            params["until"] = end

        while token:
            resp = self.client.http_request("GET", path, params=params)
            if resp:
                token = resp.get("token", None)
                params["token"] = token
                items = resp[key]
                for i in items:
                    yield i
            else:
                return


class Agents(Resource):
    def list(self, status=None, **kwargs):
        status = "offline" if status == "offline" else "online"
        return super(Agents, self).list(status=status, **kwargs)


class Alerts(Resource):
    def list(self, dismissed=False, **kwargs):
        status = "dismissed" if dismissed else "active"
        return super(Alerts, self).list(status=status, **kwargs)

    def severity_counts(self):
        path = "{}/severity-counts".format(self.name)
        resp = self.client.http_request("GET", path=path)
        return resp

    def events(self, alert_id=""):
        path = "{}/{}/events".format(self.name, alert_id)
        resp = self.client.http_request("GET", path)
        return resp


class Vulnerabilities(Resource):
    def list(self, active=None, **kwargs):
        path_extra = ""
        key = "cves"
        return super(Vulnerabilities, self).list(key=key, path_extra=path_extra, active=active, **kwargs)

    def suppressed(self, active=None):
        params = {}
        if active is not None:
            params["active"] = active
        return super(Vulnerabilities, self).list(key="suppressions", path_extra="suppressions", active=active)

    def package(self, package, status=None):
        path = "{}/package/{}".format(self.name, package)
        params = {}
        if status is not None:
            params["status"] = status
        resp = self.client.http_request("GET", path, params=params)
        return resp

    def affected_servers(self, cve):
        path = "{}/{}/servers".format(self.name, cve)
        resp = self.client.http_request("GET", path)
        return resp


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

    def agents_for_ruleset(self, agent_id):
        path = "rulesets/{}".format(agent_id)
        resp = self.client.http_request("GET", path, params={"agentId": agent_id})
        return resp


class Ec2Servers(Resource):
    def list(self, monitored=None, **kwargs):
        self.name = "aws"
        return super(Ec2Servers, self).list(path_extra="ec2/", key="servers", monitored=monitored, **kwargs)

