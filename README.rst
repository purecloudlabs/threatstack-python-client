==========================
Threat Stack Python Client
==========================

|Build Status| |PyPi| |Docs|


.. |Build Status| image:: https://travis-ci.org/MyPureCloud/threatstack-python-client.svg?branch=master
    :target: https://travis-ci.org/MyPureCloud/threatstack-python-client

.. |PyPi| image:: https://badge.fury.io/py/threatstack.svg
    :target: https://badge.fury.io/py/threatstack

.. |Docs| image:: https://readthedocs.org/projects/threatstack-python-client/badge/?version=latest&style=flat
    :target: https://threatstack-python-client.readthedocs.io/en/latest/
    :alt: Read the docs

A Python library for Threat Stack's REST API.

Quickstart
============

Resource Types
--------------
- agents
- alerts
- vulnerabilities
- rulesets & rules 
- servers

Installation
------------

Install via **pip**::
    
    pip install threatstack

Usage
-----

Create a new client::

    from threatstack import ThreatStack
    client = ThreatStack(api_key="<API_KEY>", org_id="<ORG_ID>", user_id="<USER_ID>")

List resources::

    agents = client.agents.list(status='online')

    # iterate over results
    for agent in agents:
        print agent["id"]

Get a single resource::

    agent = client.agents.get("<AGENT_ID">)

Using a date range::

    alerts = client.alerts.list(status="active", start="2017-05-01", end="2017-05-31")


Documentation
=============

See full documentation and usage examples at http://threatstack-python-client.readthedocs.io/


