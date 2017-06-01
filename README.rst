==========================
Threat Stack Python Client
==========================

.. image:: https://travis-ci.org/MyPureCloud/threatstack-python-client.svg?branch=master
    :target: https://travis-ci.org/MyPureCloud/threatstack-python-client

.. image:: https://badge.fury.io/py/threatstack.svg
    :target: https://badge.fury.io/py/threatstack

A Python library for Threat Stack's REST API.

Quickstart
============

Resource Types
--------------
- agents
- alerts
- logs
- organizations
- policies

Installation
------------

Install via **pip**::
    
    pip install threatstack

Usage
-----

Create a new client::

    from threatstack import ThreatStack
    client = ThreatStack("<API_KEY>")

List resources::

    agents = client.agents.list()

    # iterate over results
    for agent in agents:
        print agent["id"]

Using a date range::

    alerts = client.alerts.list(start="2017-05-01", end="2017-05-31")

Pagination::

    agents = client.agents.list(page=2, count=10)

Only retrieve agent hostname and IP address::

    agents = client.agents.list(fields=["hostname", "ip_address"])

Get a single resource::

    agent = client.agents.get("<AGENT_ID">)


Documentation
=============

See full documentation and usage examples at http://threatstack-python-client.readthedocs.io/


