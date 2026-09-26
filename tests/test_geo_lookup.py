from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.analyzers.geo_lookup import GeoLookup


class TestGeoLookup:
    def test_returns_none_when_no_db(self, tmp_path: Path) -> None:
        geo = GeoLookup(
            city_db=tmp_path / "nonexistent.mmdb",
            asn_db=tmp_path  / "nonexistent.mmdb",
        )
        result = geo.lookup("1.2.3.4")
        assert result["geo_country"] is None
        assert result["geo_city"]    is None
        assert result["geo_asn"]     is None

    def test_city_lookup_mocked(self) -> None:
        mock_city = MagicMock()
        mock_city.country.iso_code = "RU"
        mock_city.city.name        = "Moscow"

        geo = GeoLookup.__new__(GeoLookup)
        geo._city_reader = MagicMock()
        geo._city_reader.city.return_value = mock_city
        geo._asn_reader  = None

        result = geo.lookup("185.220.101.45")
        assert result["geo_country"] == "RU"
        assert result["geo_city"]    == "Moscow"
        assert result["geo_asn"]     is None

    def test_asn_lookup_mocked(self) -> None:
        mock_asn = MagicMock()
        mock_asn.autonomous_system_number       = 12389
        mock_asn.autonomous_system_organization = "Rostelecom"

        geo = GeoLookup.__new__(GeoLookup)
        geo._city_reader = None
        geo._asn_reader  = MagicMock()
        geo._asn_reader.asn.return_value = mock_asn

        result = geo.lookup("185.220.101.45")
        assert result["geo_asn"] == "AS12389 Rostelecom"

    def test_private_ip_returns_none(self) -> None:
        import geoip2.errors

        geo = GeoLookup.__new__(GeoLookup)
        geo._city_reader = MagicMock()
        geo._city_reader.city.side_effect = geoip2.errors.AddressNotFoundError("")
        geo._asn_reader  = None

        result = geo.lookup("192.168.1.1")
        assert result["geo_country"] is None
