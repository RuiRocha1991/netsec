from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.analyzers.threat_intel import ThreatIntel


@pytest.fixture
def intel(tmp_path: Path) -> ThreatIntel:
    return ThreatIntel(api_key="test_key", cache_path=tmp_path / "cache.db")


class TestThreatIntel:
    def test_no_api_key_returns_zero(self, tmp_path: Path) -> None:
        intel = ThreatIntel(api_key="", cache_path=tmp_path / "cache.db")
        score, country = intel.check_ip("1.2.3.4")
        assert score == 0
        assert country is None

    def test_cache_hit_avoids_api_call(self, intel: ThreatIntel) -> None:
        # Popular a cache manualmente
        intel._set_cache("1.2.3.4", 87, "RU")
        with patch.object(intel.session, "get") as mock_get:
            score, country = intel.check_ip("1.2.3.4")
            mock_get.assert_not_called()
        assert score == 87
        assert country == "RU"

    def test_api_called_when_no_cache(self, intel: ThreatIntel) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {"abuseConfidenceScore": 95, "countryCode": "CN"}
        }
        mock_resp.raise_for_status.return_value = None
        with patch.object(intel.session, "get", return_value=mock_resp):
            score, country = intel.check_ip("5.6.7.8")
        assert score == 95
        assert country == "CN"

    def test_cache_populated_after_api_call(self, intel: ThreatIntel) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {"abuseConfidenceScore": 50, "countryCode": "BR"}
        }
        mock_resp.raise_for_status.return_value = None
        with patch.object(intel.session, "get", return_value=mock_resp):
            intel.check_ip("9.9.9.9")
        # Segunda chamada deve usar cache
        with patch.object(intel.session, "get") as mock_get:
            score, _ = intel.check_ip("9.9.9.9")
            mock_get.assert_not_called()
        assert score == 50

    def test_api_error_returns_zero(self, intel: ThreatIntel) -> None:
        import requests
        with patch.object(intel.session, "get", side_effect=requests.ConnectionError()):
            score, country = intel.check_ip("1.2.3.4")
        assert score == 0
