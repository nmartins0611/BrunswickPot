"""
GeoIP Enricher
Uses MaxMind GeoIP2 database for IP geolocation (offline, no API limits)
"""

from typing import Dict, Any
import logging

try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

from .base import BaseEnricher

logger = logging.getLogger(__name__)


class GeoIPEnricher(BaseEnricher):
    """Enricher for IP geolocation using MaxMind GeoIP2"""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize GeoIP enricher

        Args:
            config: GeoIP configuration including database paths
        """
        super().__init__(config, enricher_name="GeoIPEnricher")

        if not GEOIP2_AVAILABLE:
            self.logger.warning("geoip2 library not available. Install with: pip install geoip2")
            self.enabled = False
            return

        self.city_db_path = config.get('database_path', '/var/lib/GeoIP/GeoLite2-City.mmdb')
        self.city_reader = None

        if self.enabled:
            try:
                self.city_reader = geoip2.database.Reader(self.city_db_path)
                self.logger.info(f"Loaded GeoIP2 City database from {self.city_db_path}")
            except Exception as e:
                self.logger.error(f"Failed to load GeoIP2 database: {e}")
                self.logger.info("Download GeoLite2 databases from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
                self.enabled = False

    def enrich(self, ip: str) -> Dict[str, Any]:
        """
        Enrich IP with geolocation data

        Args:
            ip: IP address to lookup

        Returns:
            Dictionary with geolocation data
        """
        if not self.enabled or not self.city_reader:
            return {}

        try:
            response = self.city_reader.city(ip)

            geoip_data = {
                'country': response.country.iso_code or 'Unknown',
                'country_name': response.country.name or 'Unknown',
                'city': response.city.name or 'Unknown',
                'postal_code': response.postal.code or 'Unknown',
                'latitude': response.location.latitude if response.location.latitude else None,
                'longitude': response.location.longitude if response.location.longitude else None,
                'timezone': response.location.time_zone or 'Unknown',
                'accuracy_radius': response.location.accuracy_radius if response.location.accuracy_radius else None,
            }

            # Add continent if available
            if response.continent.name:
                geoip_data['continent'] = response.continent.name

            # Add subdivisions (states/provinces) if available
            if response.subdivisions:
                geoip_data['subdivision'] = response.subdivisions.most_specific.name

            self.logger.debug(f"GeoIP enriched {ip}: {geoip_data.get('city')}, {geoip_data.get('country')}")
            return geoip_data

        except geoip2.errors.AddressNotFoundError:
            self.logger.debug(f"IP not found in GeoIP database: {ip}")
            return {
                'country': 'Unknown',
                'city': 'Unknown',
                'error': 'IP not found in database'
            }
        except Exception as e:
            self.logger.error(f"GeoIP lookup error for {ip}: {e}")
            return {
                'country': 'Unknown',
                'city': 'Unknown',
                'error': str(e)
            }

    def close(self):
        """Close database readers"""
        if self.city_reader:
            self.city_reader.close()
            self.logger.info("GeoIP database closed")
