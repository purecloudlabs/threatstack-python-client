V1 Client Documentation
=======================

Resource Types
--------------
- agents
- alerts
- logs
- organizations
- policies

For details on each resource please refer to the `Threat Stack API documentation <https://app.threatstack.com/api/docs/>`_.


Create a new client
-------------------
Import and create a new Threat Stack client::

    from threatstack import ThreatStack

    client = ThreatStack("<API_KEY>")

Additional *optional* parameters can be specified when creating a new client object::

    # default api_version: 1 
    # default http request timeout = 120 

    client = ThreatStack(
        api_key=<"API_KEY>",
        org_id="<ORG_ID>",
        api_version=1,
        timeout=120
    )

Listing Resources
-----------------

All resource types support a *list* method which returns a generator.  The generator can be used to iterate over the results.  NOTE: The *list* method uses the default time range for the resouce (see Time Ranges below).

Listing Agents::

    agents = client.agents.list()

    # iterate over results
    for agent in agents:
        print agent["id"]

Listing Alerts::

    alerts = client.alerts.list()

Listing Logs::

    logs = client.logs.list()

Listing Organizations::

    orgs = client.organizations.list()

Listing Policies::

    policies = client.policies.list()



**Time Ranges**

Each resource type has a default date/time range that is applied by the Threat Stack API when listing items.  Please refer to the `Threat Stack API documentation <https://app.threatstack.com/api/docs/>`_ for additional information on these default date/time ranges.  To specify a date/time range other than the default, the **start** and **end** parameters can be used.

Using a date range::

    alerts = client.alerts.list(start="2017-05-01", end="2017-05-31")

Using a date and time range::

    alerts = client.alerts.list(
        start="2017-05-01 08:00:00",
        end="2017-05-01 09:00:00"
    )

Using *datetime*::

    from datetime import datetime, timedelta

    end = datetime.now()
    start = end - timedelta(hours=1)
    alerts = client.alerts.list(start=start, end=end)



**Pagination**

The Agents, Alerts, and Logs resource types support pagination.  This allows you to control the page and count values when retrieving a list of items.  Please refer to the `Threat Stack API documentation <https://app.threatstack.com/api/docs/>`_ for additional information on pagination. ::

    # default page: 0
    # default count: 20
    
    agents = client.agents.list(page=2, count=10)



**Field Filters**

When listing resources you can limit the fields that are returned from the ThreatStack API for each resource.  Please refer to the `Threat Stack API documentation <https://app.threatstack.com/api/docs/>`_ for additional information on partial responses.

Only retrieve agent hostname and IP address::

    agents = client.agents.list(fields=["hostname", "ip_address"])


Getting a Specific Resource
---------------------------

All resource types other than Logs and Organizations support the *get* method.  This method allows you to retrieve details about a specific resource given its unique identifier.  The *get* method returns a Python dict.

Getting an Agent::

    agent = client.agents.get("<AGENT_ID>")

Getting an Alert::

    alert = client.alerts.get("<ALERT_ID>")

Getting a Policy::

    policy = client.policy.get("<POLICY_ID>")

If the resource is **not found** by the ThreatStack API, and empty dict is returned from the client. ::

    agent = client.agents.get("<AGENT_ID">)
    if agent:
        print agent
    else:
        print "Agent not found"


Additional Methods
------------------

Organizations
-------------

The Organizations resource has a *users* method which returns a list of users for a given organization.

Get users for an Organization::

    users = client.organization.users("<org_id>")

Additional Examples
-------------------

Retrieve list of alert ID's from the last hour and then get details for each alert::

    from datetime import datetime, timedelta
    from threatstack import ThreatStack, ThreatStackAPIError

    client = ThreatStack("<API_KEY>")

    now = datetime.now()
    one_hour_ago = now - timedelta(hours=1)

    try:
        alerts = client.alerts.list(start=one_hour_ago, end=now, fields=["id"])

        for alert in alerts:
            details = client.alerts.get(alert["id"])

    except ThreatStackAPIError:
        print "The ThreatStack API returned an error response."
