.. Threat Stack Python Client documentation master file, created by
   sphinx-quickstart on Wed May 31 10:35:08 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

======================================================
Welcome to Threat Stack Python Client's documentation!
======================================================

The Threat Stack Python Client is a library which allows Python developers to write software that makes use of Threat Stack REST API.

.. toctree::
   :maxdepth: 1
   :caption: Contents:

   v1/index.rst


Installation
============

Install via **pip**::
    
    pip install threatstack


Usage
=====

Resource Types
--------------
- agents
- alerts
- cve vulnerabilities
- rulesets and rules
- servers

For details on each resource please refer to the `Threat Stack API documentation <https://apidocs.threatstack.com/v2/v2-documentation>`_.


Create a new client
-------------------
Import and create a new Threat Stack client::

    from threatstack import ThreatStack

    client = ThreatStack(api_key="<API_KEY>", org_id="<ORG_ID>")

Additional *optional* parameters can be specified when creating a new client object::

    # default api_version: 2 
    # default http request timeout = 120 

    client = ThreatStack(
        api_key=<"API_KEY>",
        org_id="<ORG_ID>",
        api_version=[1 or 2],
        timeout=<SECONDS>
    )

See 'V1 Client Documentation' for using the V1 ThreatStack API Client.

Time Ranges
-----------

Time ranges can be specified when listing resources using the `start` and `end` parameters::

    now = datetime.now()
    one_hour_ago = now - timedelta(hours=1)

    alerts = client.alerts.list(start=one_hour_ago.isoformat(), end=now.isoformat())

    for alert in alerts:
        details = client.alerts.get(alert["id"])


Agents
------

Listing Agents::

    agents = client.agents.list()

    # iterate over results
    for agent in agents:
        print agent["id"]

    # query parameters
    agents = client.agents.list(type=<"monitor" or "investigate">, hostname=<"hostname">, instanceId="<instanceId">)

Offline Agents::

    By default only online agents will be listed. To get offline agents set offline to True.

    offline_agents = client.agents.list(offline=True)

Get agent by ID::

    agent = client.agents.get("<agent_id>")


Alerts
------
Listing Alerts::

    alerts = client.alerts.list(severity=<1, 2, or 3>)

Get Alert by ID::

	alert = client.alerts.get("<alert_id>")

List all dismissed alerts::

	dismissed = client.alerts.list(dismissed=True)

Get severity counts for alerts::

	sev_counts = client.alerts.severity_counts()

Get an event for an alert::

    event = client.alerts.event(alert_id="<alert_id>", event_id="<event_id>")


CVE Vulnerabilities
-------------------

List all vulnerabilities::

    vulns = client.vulnerabilities.list()

    # query parameters
    vulns = client.vulnerabilities.list(package="<package_name>", server="<instanceId/hostname>", agent="<agentId>")

Get a vulnerability by CVE number::

	cve = client.vulnerabilities.get("<cve_number>")

List all suppressed vulnerabilities::

    vulns = client.vulnerabilties.list(suppressed=True)

    # same query params can be used as with list
    vulns = client.vulnerabilities.list(suppressed=True, package="<package_name>", server="<instanceId/hostname>", agent="<agentId>")


Rulesets & Rules
----------------

List all rulesets::

    rulesets = client.rulesets.list()

    # query parameters
    rulesets = client.rulesets.list(agentId="<agent_id>")

Get a ruleset::

    ruleset = client.ruleset.get("<ruleset_id>")

Get all rules for a ruleset::

    rules = client.ruleset.rules(ruleset_id="<ruleset_id>")

Get a rule for a ruleset::

    rule = client.ruleset.rules(ruleset_id="<ruleset_id>", rule_id="<rule_id>")


Servers
-------

Get all servers::

    servers = client.servers.list()

Get all non-monitored servers::

    non_monitored = client.servers.list(non_monitored=True)
