from types import GeneratorType

import pytest
import responses

from threatstack import ThreatStack, ThreatStackClientError


@responses.activate
def test_list_organizations():
    responses.add(responses.GET, "https://app.threatstack.com/api/v1/organizations",
                  content_type="application/json",
                  body='[ \
                            {"role": "user", "id": "acbd18db4cc2f85cedef654fccc4a4d8", "name": "Foo\'s Organization"}, \
                            {"role": "user", "id": "37b51d194a7513e45b56f6524f2d51f2", "name": "Bar\'s Organization"} \
                         ]'
                  )

    ts = ThreatStack("test_api_key")
    response = ts.organizations.list()
    assert isinstance(response, GeneratorType)

    count = 0
    for org in response:
        count += 1

    assert count == 2


def test_get_organziation():
    with pytest.raises(ThreatStackClientError) as ex:
        ts = ThreatStack("test_api_key")
        org = ts.organizations.get()

        assert "API method not supported" in str(ex.value)


@responses.activate
def test_get_organization_users():
    responses.add(responses.GET, "https://app.threatstack.com/api/v1/organizations/acbd18db4cc2f85cedef654fccc4a4dG8/users",
                  content_type="application/json",
                  body='[ \
                            { \
                                "id": "1010101010ababababab2020", \
                                "display_name": "John Doe", \
                                "name": {"last": "Doe", "first": "John"}, \
                                "updated_at": "2013-10-02T16:31:21.000Z", \
                                "organization_id": "37b51d194a7513e45b56f6524f2d51f2", \
                                "role": "owner", \
                                "email": "john.doe@johndoe.com" \
                            }, \
                            { \
                                "id": "1010101010ababababab2021", \
                                "display_name": "Charles Xavier", \
                                "name": {"last": "Xavier", "first": "Charles"}, \
                                "updated_at": "2013-09-16T21:24:06.000Z", \
                                "organization_id": "37b51d194a7513e45b56f6524f2d51f2", \
                                "role": "user", \
                                "email": "charles.xavier@xmen.com" \
                            } \
                        ]'
                  )

    ts = ThreatStack("test_api_key")
    response = ts.organizations.users("acbd18db4cc2f85cedef654fccc4a4dG8")
    assert isinstance(response, GeneratorType)

    count = 0
    for user in response:
        assert user["organization_id"] == "37b51d194a7513e45b56f6524f2d51f2"
        count += 1

    assert count == 2
