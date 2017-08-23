import pytest

from threatstack import (
    ThreatStack,
    ThreatStackClientError,
    APIRateLimitError
)


def test_missing_api_key():

    with pytest.raises(ThreatStackClientError) as ex:
        ts = ThreatStack(api_version=2)

        assert 'api_key is required' in str(ex.value)

def test_missing_api_version():

    with pytest.raises(ThreatStackClientError) as ex:
        ts = ThreatStack(api_key="test_api_key")

        assert 'Invalid API version' in str(ex.value)
