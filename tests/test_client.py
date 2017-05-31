import pytest
import requests

from threatstack import (
    ThreatStack,
    ThreatStackClientError,
    APIRateLimitError
)

def test_missing_api_key():

    with pytest.raises(ThreatStackClientError) as ex:
        ts = ThreatStack()

        assert 'API key not specified' in str(ex.value)
