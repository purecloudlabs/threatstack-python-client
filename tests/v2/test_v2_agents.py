from types import GeneratorType

import responses
import pytest

from threatstack import ThreatStack


@responses.activate
def test_v2_list_agents():
    responses.add(responses.GET, "https://api.threatstack.com/v2/agents",
                  content_type="application/json",
                  body='{ \
                            "token": "", \
                            "agents": [ \
                                { \
                                    "activated_at": "2014-01-31T14:36:24.359Z", \
                                    "pause": false, \
                                    "online": false, \
                                    "enabled": true, \
                                    "updated_at": "2014-01-31T01:32:54.000Z", \
                                    "last_reported_at": "2014-02-03T22:39:28.912Z", \
                                    "created_at": "2014-01-31T01:32:54.000Z", \
                                    "ip_address": "189.173.23.133", \
                                    "version": "1.0.8", \
                                    "status": "active", \
                                    "name": "precise64", \
                                    "description": "", \
                                    "hostname": "webserver-2", \
                                    "agent_id": "524c4a59a086e11959000009-6cc8d9b0-8a17-11e3-a2e3-ffced68b988625dda8300db4f718", \
                                    "id": "52eafd46e5777f3a26000008", \
                                    "policy_id": "524c4b9aa086e1195900000d", \
                                    "organization_id": "524c4a59a086e11959000002" \
                                }, \
                                { \
                                    "activated_at": "2014-01-31T14:36:24.359Z", \
                                    "pause": false, \
                                    "online": true, \
                                    "enabled": true, \
                                    "updated_at": "2014-01-31T01:32:54.000Z", \
                                    "last_reported_at": "2014-02-03T22:39:28.912Z", \
                                    "created_at": "2014-01-31T01:32:54.000Z", \
                                    "ip_address": "189.173.23.134", \
                                    "version": "1.0.8", \
                                    "status": "active", \
                                    "name": "precise64", \
                                    "description": "", \
                                    "hostname": "webserver-2", \
                                    "agent_id": "524c4a59a086e11959000009-6cc8d9b0-8a17-11e3-a2e3-ffced68b988625dda8300db4f719", \
                                    "id": "52eafd46e5777f3a26000009", \
                                    "policy_id": "524c4b9aa086e1195900000d", \
                                    "organization_id": "524c4a59a086e11959000002" \
                                } \
                             ] \
                        }'
                      )

    ts = ThreatStack(api_key="test_api_key", org_id="test_org_id", api_version=2)
    response = ts.agents.list()
    assert isinstance(response, GeneratorType)

    count = 0
    for agent in response:
        assert agent["organization_id"] == "524c4a59a086e11959000002"
        count += 1

    assert count == 2

@responses.activate
def test_get_agent():
    responses.add(responses.GET, "https://api.threatstack.com/v2/agents/52eafd46e5777f3a26000009",
                  content_type="application/json",
                  body='{ \
                            "activated_at": "2014-01-31T14:36:24.359Z", \
                            "pause": false, \
                            "online": true, \
                            "enabled": true, \
                            "updated_at": "2014-01-31T01:32:54.000Z", \
                            "last_reported_at": "2014-02-03T22:39:28.912Z", \
                            "created_at": "2014-01-31T01:32:54.000Z", \
                            "ip_address": "189.173.23.134", \
                            "version": "1.0.8", \
                            "status": "active", \
                            "name": "precise64", \
                            "description": "", \
                            "hostname": "webserver-2", \
                            "agent_id": "524c4a59a086e11959000009-6cc8d9b0-8a17-11e3-a2e3-ffced68b988625dda8300db4f719", \
                            "id": "52eafd46e5777f3a26000009", \
                            "policy_id": "524c4b9aa086e1195900000d", \
                            "organization_id": "524c4a59a086e11959000002" \
                        }'
                  )

    ts = ThreatStack(api_key="test_api_key", org_id="test_org_id", api_version=2)
    response = ts.agents.get("52eafd46e5777f3a26000009")
    assert isinstance(response, dict)

    assert response["hostname"] == "webserver-2"
