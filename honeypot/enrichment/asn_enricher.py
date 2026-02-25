"""
ASN Enricher
Uses MaxMind GeoIP2 ASN database for autonomous system information (offline)
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


class ASNEnricher(BaseEnricher):
    """Enricher for ASN/ISP information using MaxMind GeoIP2"""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize ASN enricher

        Args:
            config: ASN configuration including database path
        """
        super().__init__(config, enricher_name="ASNEnricher")

        if not GEOIP2_AVAILABLE:
            self.logger.warning("geoip2 library not available. Install with: pip install geoip2")
            self.enabled = False
            return

        self.asn_db_path = config.get('asn_database_path', '/var/lib/GeoIP/GeoLite2-ASN.mmdb')
        self.asn_reader = None

        if self.enabled:
            try:
                self.asn_reader = geoip2.database.Reader(self.asn_db_path)
                self.logger.info(f"Loaded GeoIP2 ASN database from {self.asn_db_path}")
            except Exception as e:
                self.logger.error(f"Failed to load GeoIP2 ASN database: {e}")
                self.logger.info("Download GeoLite2 ASN database from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
                self.enabled = False

    def enrich(self, ip: str) -> Dict[str, Any]:
        """
        Enrich IP with ASN/ISP data

        Args:
            ip: IP address to lookup

        Returns:
            Dictionary with ASN data
        """
        if not self.enabled or not self.asn_reader:
            return {}

        try:
            response = self.asn_reader.asn(ip)

            asn_data = {
                'autonomous_system_number': response.autonomous_system_number,
                'autonomous_system_organization': response.autonomous_system_organization or 'Unknown',
                'network': str(response.network) if response.network else 'Unknown',
            }

            self.logger.debug(f"ASN enriched {ip}: AS{asn_data['autonomous_system_number']} ({asn_data['autonomous_system_organization']})")
            return asn_data

        except geoip2.errors.AddressNotFoundError:
            self.logger.debug(f"IP not found in ASN database: {ip}")
            return {
                'autonomous_system_number': None,
                'autonomous_system_organization': 'Unknown',
                'error': 'IP not found in database'
            }
        except Exception as e:
            self.logger.error(f"ASN lookup error for {ip}: {e}")
            return {
                'autonomous_system_number': None,
                'autonomous_system_organization': 'Unknown',
                'error': str(e)
            }

    def close(self):
        """Close database reader"""
        if self.asn_reader:
            self.asn_reader.close()
            self.logger.info("ASN database closed")
