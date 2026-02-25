"""
Reputation Enricher
Uses AbuseIPDB API for IP reputation and abuse confidence scores
"""

from typing import Dict, Any
import logging
import requests
import time

from .base import BaseEnricher

logger = logging.getLogger(__name__)


class ReputationEnricher(BaseEnricher):
    """Enricher for IP reputation using AbuseIPDB"""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize reputation enricher

        Args:
            config: AbuseIPDB configuration including API key
        """
        super().__init__(config, enricher_name="ReputationEnricher")

        self.api_key = config.get('api_key')
        self.confidence_threshold = config.get('confidence_threshold', 75)
        self.max_requests_per_day = config.get('max_requests_per_day', 1000)
        self.api_url = 'https://api.abuseipdb.com/api/v2/check'

        # Rate limiting
        self.request_count = 0
        self.request_reset_time = time.time() + 86400  # Reset after 24 hours

        if self.enabled and not self.api_key:
            self.logger.warning("AbuseIPDB API key not configured, disabling reputation enrichment")
            self.enabled = False

        if self.enabled:
            self.logger.info(f"AbuseIPDB enricher initialized (confidence threshold: {self.confidence_threshold})")

    def enrich(self, ip: str) -> Dict[str, Any]:
        """
        Enrich IP with reputation data from AbuseIPDB

        Args:
            ip: IP address to lookup

        Returns:
            Dictionary with reputation data
        """
        if not self.enabled:
            return {}

        # Check rate limit
        if time.time() > self.request_reset_time:
            # Reset counter after 24 hours
            self.request_count = 0
            self.request_reset_time = time.time() + 86400

        if self.request_count >= self.max_requests_per_day:
            self.logger.warning(f"AbuseIPDB API rate limit reached ({self.max_requests_per_day}/day)")
            return {
                'error': 'Rate limit exceeded',
                'abuse_confidence_score': 0
            }

        try:
            headers = {
                'Accept': 'application/json',
                'Key': self.api_key
            }

            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }

            response = requests.get(
                self.api_url,
                headers=headers,
                params=params,
                timeout=5
            )

            self.request_count += 1

            if response.status_code == 200:
                data = response.json().get('data', {})

                reputation_data = {
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'num_distinct_users': data.get('numDistinctUsers', 0),
                    'last_reported_at': data.get('lastReportedAt'),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'is_public': data.get('isPublic', True),
                    'is_tor': data.get('isTor', False),
                    'country_code': data.get('countryCode'),
                    'usage_type': data.get('usageType'),
                    'isp': data.get('isp'),
                    'domain': data.get('domain'),
                }

                # Add risk assessment
                score = reputation_data['abuse_confidence_score']
                if score >= 90:
                    reputation_data['risk_level'] = 'critical'
                elif score >= self.confidence_threshold:
                    reputation_data['risk_level'] = 'high'
                elif score >= 50:
                    reputation_data['risk_level'] = 'medium'
                else:
                    reputation_data['risk_level'] = 'low'

                self.logger.debug(f"AbuseIPDB enriched {ip}: score={score}, reports={reputation_data['total_reports']}")
                return reputation_data

            elif response.status_code == 429:
                self.logger.warning(f"AbuseIPDB API rate limit hit (HTTP 429)")
                return {
                    'error': 'Rate limit exceeded',
                    'abuse_confidence_score': 0
                }

            else:
                self.logger.error(f"AbuseIPDB API error: HTTP {response.status_code}")
                return {
                    'error': f'HTTP {response.status_code}',
                    'abuse_confidence_score': 0
                }

        except requests.exceptions.Timeout:
            self.logger.warning(f"AbuseIPDB API timeout for {ip}")
            return {
                'error': 'Timeout',
                'abuse_confidence_score': 0
            }
        except Exception as e:
            self.logger.error(f"AbuseIPDB lookup error for {ip}: {e}")
            return {
                'error': str(e),
                'abuse_confidence_score': 0
            }

    def get_stats(self) -> Dict[str, Any]:
        """Get API usage statistics"""
        remaining = max(0, self.max_requests_per_day - self.request_count)
        time_until_reset = max(0, self.request_reset_time - time.time())

        return {
            'requests_used': self.request_count,
            'requests_remaining': remaining,
            'max_requests_per_day': self.max_requests_per_day,
            'time_until_reset_hours': time_until_reset / 3600
        }
