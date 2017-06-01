from types import GeneratorType

import pytest
import responses

from threatstack import ThreatStack, ThreatStackClientError


@responses.activate
def test_list_logs():
    responses.add(responses.GET, "https://app.threatstack.com/api/v1/logs",
                  content_type="application/json",
                  body='[ \
                         { \
                             "timestamp": 1398277257000, \
                             "user": "John Doe", \
                             "type": "queue", \
                             "action": "add", \
                             "description": "Event of type audit added to Queue", \
                             "context": [ \
                                 { \
                                     "id": "20c2bac3-86c2-88c3-2f1c-12c2b5c3b153", \
                                     "type": "audit", \
                                     "agent": { \
                                         "name": "precise64", \
                                         "policy_id": "524c4b9aa086e1195900000d", \
                                         "id": "52fd46e3277f3a26000008" \
                                     }, \
                                     "name": "/bin/nc.openbsd" \
                                 } \
                             ], \
                             "source": "queue:add", \
                             "user_id": "524c4a59a086e11959000008", \
                             "organization_id": "524c4a59a086e11959000009" \
                         }, \
                         { \
                             "timestamp": 1398277257000, \
                             "user": "John Doe", \
                             "type": "queue", \
                             "action": "add", \
                             "description": "Event of type audit added to Queue", \
                             "context": [ \
                                 { \
                                     "id": "20c2bac3-86c2-88c3-2f1c-12c2b5c3b153", \
                                     "type": "audit", \
                                     "agent": { \
                                         "name": "precise64", \
                                         "policy_id": "524c4b9aa086e1195900000d", \
                                         "id": "52fd46e3277f3a26000008" \
                                     }, \
                                     "name": "/bin/nc.openbsd" \
                                 } \
                             ], \
                             "source": "queue:add", \
                             "user_id": "524c4a59a086e11959000008", \
                             "organization_id": "524c4a59a086e11959000009" \
                         } \
                     ]'
                  )

    ts = ThreatStack("test_api_key")
    response = ts.logs.list(page=1)
    assert isinstance(response, GeneratorType)

    count = 0
    for org in response:
        count += 1

    assert count == 2


def test_get_log():
    with pytest.raises(ThreatStackClientError) as ex:
        ts = ThreatStack("test_api_key")
        org = ts.logs.get()

        assert "API method not supported" in str(ex.value)
