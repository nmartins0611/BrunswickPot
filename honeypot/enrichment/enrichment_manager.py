"""
Enrichment Manager
Orchestrates all enrichers with caching and parallel execution
"""

from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

from .cache import EnrichmentCache
from .geoip_enricher import GeoIPEnricher
from .asn_enricher import ASNEnricher
from .reputation_enricher import ReputationEnricher

logger = logging.getLogger(__name__)


class EnrichmentManager:
    """Manages threat intelligence enrichment pipeline"""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize enrichment manager

        Args:
            config: Enrichment configuration dictionary
        """
        self.config = config
        self.enabled = config.get('enabled', False)

        # Initialize cache
        cache_config = config.get('cache', {})
        cache_ttl = cache_config.get('ttl', 86400)  # Default: 24 hours
        cache_max_size = cache_config.get('max_size', 10000)
        self.cache = EnrichmentCache(max_size=cache_max_size, ttl_seconds=cache_ttl)

        # Initialize enrichers
        self.enrichers = []

        if self.enabled:
            # GeoIP enricher
            if config.get('geoip', {}).get('enabled', False):
                try:
                    enricher = GeoIPEnricher(config['geoip'])
                    if enricher.enabled:
                        self.enrichers.append(('geoip', enricher))
                except Exception as e:
                    logger.error(f"Failed to initialize GeoIP enricher: {e}")

            # ASN enricher
            if config.get('geoip', {}).get('enabled', False):  # ASN uses same config section
                try:
                    enricher = ASNEnricher(config['geoip'])
                    if enricher.enabled:
                        self.enrichers.append(('asn', enricher))
                except Exception as e:
                    logger.error(f"Failed to initialize ASN enricher: {e}")

            # AbuseIPDB enricher
            if config.get('abuseipdb', {}).get('enabled', False):
                try:
                    enricher = ReputationEnricher(config['abuseipdb'])
                    if enricher.enabled:
                        self.enrichers.append(('reputation', enricher))
                except Exception as e:
                    logger.error(f"Failed to initialize AbuseIPDB enricher: {e}")

            logger.info(f"EnrichmentManager initialized with {len(self.enrichers)} enrichers")
        else:
            logger.info("Enrichment disabled")

    def enrich(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich event with threat intelligence

        Args:
            event: Event dictionary containing source_ip

        Returns:
            Event with enrichment data added
        """
        if not self.enabled or not self.enrichers:
            return event

        source_ip = event.get('source_ip')
        if not source_ip or source_ip == 'unknown':
            return event

        # Check cache first
        cached_enrichment = self.cache.get(source_ip)
        if cached_enrichment:
            event['enrichment'] = cached_enrichment
            return event

        # Perform enrichment
        enrichment_data = self._enrich_ip(source_ip)

        # Cache result
        if enrichment_data:
            self.cache.set(source_ip, enrichment_data)

        # Add to event
        event['enrichment'] = enrichment_data

        return event

    def _enrich_ip(self, ip: str) -> Dict[str, Any]:
        """
        Enrich IP address with all enabled enrichers in parallel

        Args:
            ip: IP address to enrich

        Returns:
            Dictionary with all enrichment data
        """
        enrichment_data = {}

        # Run enrichers in parallel for performance
        with ThreadPoolExecutor(max_workers=len(self.enrichers)) as executor:
            # Submit all enrichment tasks
            future_to_enricher = {
                executor.submit(enricher.enrich, ip): name
                for name, enricher in self.enrichers
            }

            # Collect results as they complete
            for future in as_completed(future_to_enricher):
                enricher_name = future_to_enricher[future]
                try:
                    result = future.result(timeout=10)  # 10 second timeout per enricher
                    if result:
                        enrichment_data[enricher_name] = result
                except Exception as e:
                    logger.error(f"Enricher {enricher_name} failed for {ip}: {e}")
                    enrichment_data[enricher_name] = {'error': str(e)}

        return enrichment_data

    def enrich_ip_direct(self, ip: str) -> Dict[str, Any]:
        """
        Directly enrich an IP address (for API/MCP usage)

        Args:
            ip: IP address to enrich

        Returns:
            Enrichment data dictionary
        """
        # Check cache
        cached = self.cache.get(ip)
        if cached:
            return cached

        # Enrich
        enrichment = self._enrich_ip(ip)

        # Cache
        if enrichment:
            self.cache.set(ip, enrichment)

        return enrichment

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return self.cache.get_stats()

    def get_enricher_stats(self) -> Dict[str, Any]:
        """Get statistics from all enrichers"""
        stats = {
            'cache': self.get_cache_stats(),
            'enrichers': {}
        }

        for name, enricher in self.enrichers:
            if hasattr(enricher, 'get_stats'):
                stats['enrichers'][name] = enricher.get_stats()
            else:
                stats['enrichers'][name] = {
                    'enabled': enricher.enabled,
                    'name': enricher.enricher_name
                }

        return stats

    def close(self):
        """Clean up resources"""
        # Close enrichers
        for name, enricher in self.enrichers:
            if hasattr(enricher, 'close'):
                try:
                    enricher.close()
                except Exception as e:
                    logger.error(f"Error closing enricher {name}: {e}")

        # Clear cache
        self.cache.clear()

        logger.info("EnrichmentManager closed")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
