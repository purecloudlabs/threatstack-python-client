import httpretty
import json
import pytest
import requests
from types import GeneratorType

from threatstack import ThreatStack


@httpretty.activate
def test_list_policies():
    httpretty.register_uri(httpretty.GET, "https://app.threatstack.com/api/v1/policies",
                           content_type="application/json",
                           body='[ \
                                    { \
                                        "file_integrity_rules": [], \
                                        "updated_at": "2013-10-25T17:42:42.446Z", \
                                        "created_at": "2013-10-02T16:36:42.000Z", \
                                        "read_only": true, \
                                        "firewall_enabled": true, \
                                        "enabled": true, \
                                        "description": "This is the default policy", \
                                        "name": "Default Policy", \
                                        "id": "524c4b9aa086e1195900000a", \
                                        "organization_id": "524c4a59a086e11959000009", \
                                        "alert_policy_id": "524c4b9aa086e1195900000c", \
                                        "agent_count": 1, \
                                        "firewall_rule_count": 3, \
                                        "alert_rule_count": 2 \
                                    }, \
                                    { \
                                        "file_integrity_rules": [], \
                                        "updated_at": "2013-10-25T17:42:42.446Z", \
                                        "created_at": "2013-10-02T16:36:42.000Z", \
                                        "read_only": true, \
                                        "firewall_enabled": true, \
                                        "enabled": true, \
                                        "description": "This is the default policy", \
                                        "name": "Default Policy", \
                                        "id": "524c4b9aa086e1195900000d", \
                                        "organization_id": "524c4a59a086e11959000009", \
                                        "alert_policy_id": "524c4b9aa086e1195900000c", \
                                        "agent_count": 1, \
                                        "firewall_rule_count": 3, \
                                        "alert_rule_count": 2 \
                                    } \
                                ]'
                            )

    ts = ThreatStack("test_api_key")
    response = ts.policies.list(page=1)
    assert isinstance(response, GeneratorType)

    count = 0
    for agent in response:
        count += 1

    assert count == 2

@httpretty.activate
def test_get_policy():
    httpretty.register_uri(httpretty.GET, "https://app.threatstack.com/api/v1/policies/524c4b9aa086e1195900000a",
                           content_type="application/json",
                           body='{ \
                                    "file_integrity_rules": [], \
                                    "updated_at": "2013-10-25T17:42:42.446Z", \
                                    "created_at": "2013-10-02T16:36:42.000Z", \
                                    "read_only": true, \
                                    "firewall_enabled": true, \
                                    "enabled": true, \
                                    "description": "This is the default policy", \
                                    "name": "Default Policy", \
                                    "id": "524c4b9aa086e1195900000a", \
                                    "organization_id": "524c4a59a086e11959000009", \
                                    "alert_policy_id": "524c4b9aa086e1195900000c", \
                                    "agent_count": 1, \
                                    "firewall_rule_count": 3, \
                                    "alert_rule_count": 2 \
                                }'
                          )

    ts = ThreatStack("test_api_key")
    response = ts.policies.get("524c4b9aa086e1195900000a")
    assert isinstance(response, dict)

    assert response["id"] == "524c4b9aa086e1195900000a"
