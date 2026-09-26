from __future__ import annotations

import logging
from pathlib import Path

import geoip2.database
import geoip2.errors

logger = logging.getLogger(__name__)

_GEO_DIR  = Path("data/geoip")
_CITY_DB  = _GEO_DIR / "GeoLite2-City.mmdb"
_ASN_DB   = _GEO_DIR / "GeoLite2-ASN.mmdb"


class GeoLookup:
    """Pesquisa offline de país, cidade e ASN usando GeoLite2."""

    def __init__(
        self,
        city_db: Path = _CITY_DB,
        asn_db: Path  = _ASN_DB,
    ) -> None:
        self._city_reader: geoip2.database.Reader | None = None
        self._asn_reader:  geoip2.database.Reader | None = None
        if city_db.exists():
            self._city_reader = geoip2.database.Reader(str(city_db))
        else:
            logger.warning("GeoLite2-City.mmdb não encontrado em %s", city_db)
        if asn_db.exists():
            self._asn_reader = geoip2.database.Reader(str(asn_db))
        else:
            logger.warning("GeoLite2-ASN.mmdb não encontrado em %s", asn_db)

    def lookup(self, ip: str) -> dict[str, str | int | None]:
        """Devolve dict com country, city, asn_number, asn_org para um IP."""
        result: dict[str, str | int | None] = {
            "geo_country": None,
            "geo_city": None,
            "geo_asn": None,
        }
        if self._city_reader is not None:
            try:
                city = self._city_reader.city(ip)
                result["geo_country"] = city.country.iso_code
                result["geo_city"]    = city.city.name
            except geoip2.errors.AddressNotFoundError:
                pass  # IP privado ou não catalogado
        if self._asn_reader is not None:
            try:
                asn = self._asn_reader.asn(ip)
                result["geo_asn"] = (
                    f"AS{asn.autonomous_system_number} {asn.autonomous_system_organization}"
                )
            except geoip2.errors.AddressNotFoundError:
                pass
        return result

    def close(self) -> None:
        if self._city_reader:
            self._city_reader.close()
        if self._asn_reader:
            self._asn_reader.close()

    def __enter__(self) -> GeoLookup:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
