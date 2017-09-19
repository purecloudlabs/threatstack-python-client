from types import GeneratorType

import pytest
import responses

from threatstack import ThreatStack


@responses.activate
def test_list_alerts():
    responses.add(responses.GET, "https://api.threatstack.com/v2/alerts",
                  content_type="application/json",
                  body='{ \
                            "token": "", \
                            "alerts": [ \
                                { \
                                    "active": true, \
                                    "agent_id": "52eafd46e5777f3a26000008", \
                                    "alert_policy_id": "524c4b9aa086e1195900000c", \
                                    "count": 6, \
                                    "created_at": 1391179102237, \
                                    "dismissed": false, \
                                    "expires_at": 1391182702237, \
                                    "id": "52ebb55fdf5fb93e710002bd", \
                                    "key": "525740a144414e7d1c00000b-52eafd46e5777f3a26000008-aebc6afbb8a542a00de8fb45ccd5694b", \
                                    "last_notified_at": "2014-01-31T14:38:29.329Z", \
                                    "last_updated_at": "2014-01-31T14:39:18.682Z", \
                                    "rule_id": "525740a144414e7d1c00000b", \
                                    "severity": 1, \
                                    "title": "Netcat Detected!", \
                                    "type": "rule", \
                                    "unread": true \
                                }, \
                                { \
                                    "active": true, \
                                    "agent_id": "52eafd46e5777f3a26000008", \
                                    "alert_policy_id": "524c4b9aa086e1195900000c", \
                                    "count": 6, \
                                    "created_at": 1391179102237, \
                                    "dismissed": false, \
                                    "expires_at": 1391182702237, \
                                    "id": "52ebb55fdf5fb93e710002ba", \
                                    "key": "525740a144414e7d1c00000b-52eafd46e5777f3a26000008-aebc6afbb8a542a00de8fb45ccd5694a", \
                                    "last_notified_at": "2014-01-31T14:38:29.329Z", \
                                    "last_updated_at": "2014-01-31T14:39:18.682Z", \
                                    "rule_id": "525740a144414e7d1c00000b", \
                                    "severity": 1, \
                                    "title": "Netcat Detected!", \
                                    "type": "rule", \
                                    "unread": true \
                                } \
                           ] \
                 }'
              )

    ts = ThreatStack(api_key="test_api_key", org_id="test_org_id")
    response = ts.alerts.list()
    assert isinstance(response, GeneratorType)

    count = 0
    for alerts in response:
        count += 1

    assert count == 2

@responses.activate
def test_get_alert():
    responses.add(responses.GET, "https://api.threatstack.com/v2/alerts/52ebb55fdf5fb93e710002ba",
                  content_type="application/json",
                  body='{ \
                            "active": true, \
                            "agent_id": "52eafd46e5777f3a26000008", \
                            "alert_policy_id": "524c4b9aa086e1195900000c", \
                            "count": 6, \
                            "created_at": 1391179102237, \
                            "dismissed": false, \
                            "expires_at": 1391182702237, \
                            "id": "52ebb55fdf5fb93e710002ba", \
                            "key": "525740a144414e7d1c00000b-52eafd46e5777f3a26000008-aebc6afbb8a542a00de8fb45ccd5694a", \
                            "last_notified_at": "2014-01-31T14:38:29.329Z", \
                            "last_updated_at": "2014-01-31T14:39:18.682Z", \
                            "rule_id": "525740a144414e7d1c00000b", \
                            "severity": 1, \
                            "title": "Netcat Detected!", \
                            "type": "rule", \
                            "unread": true \
                        }'
                  )

    ts = ThreatStack(api_key="test_api_key", org_id="test_org_id")
    response = ts.alerts.get("52ebb55fdf5fb93e710002ba")
    assert isinstance(response, dict)

    assert response["id"] == "52ebb55fdf5fb93e710002ba"
