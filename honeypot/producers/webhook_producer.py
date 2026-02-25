"""
Webhook Producer
Sends honeypot events to HTTP webhooks
Refactored from original nohoney.py implementation with improved retry logic
"""

from typing import Dict, Any
import logging
import requests
import time

from .base import BaseProducer, ProducerConnectionError, ProducerSendError

logger = logging.getLogger(__name__)


class WebhookProducer(BaseProducer):
    """Producer for sending events to HTTP webhooks"""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize webhook producer

        Args:
            config: Webhook configuration dictionary
        """
        super().__init__(config, producer_name="WebhookProducer")

        self.url = config.get('url')
        self.timeout = config.get('timeout', 5)
        self.retry_attempts = config.get('retry_attempts', 3)
        self.retry_delay = config.get('retry_delay', 1)  # seconds
        self.headers = config.get('headers', {'Content-Type': 'application/json'})

        # Statistics
        self.events_sent = 0
        self.events_failed = 0

        if self.enabled:
            if not self.url:
                self.logger.error("Webhook URL is required")
                self.enabled = False
            else:
                self.logger.info(f"Webhook producer initialized (URL: {self.url})")

    def send(self, event: Dict[str, Any]) -> bool:
        """
        Send event to webhook with retry logic

        Args:
            event: Event dictionary to send

        Returns:
            bool: True if sent successfully
        """
        if not self.enabled:
            return False

        for attempt in range(self.retry_attempts):
            try:
                response = requests.post(
                    self.url,
                    json=event,
                    headers=self.headers,
                    timeout=self.timeout
                )

                if response.status_code == 200:
                    self.events_sent += 1
                    self.logger.debug(f"Event sent to webhook: {response.status_code}")
                    return True
                else:
                    self.logger.warning(
                        f"Webhook returned {response.status_code}, attempt {attempt + 1}/{self.retry_attempts}"
                    )

            except requests.exceptions.Timeout:
                self.logger.warning(f"Webhook timeout, attempt {attempt + 1}/{self.retry_attempts}")
            except requests.exceptions.ConnectionError as e:
                self.logger.warning(f"Webhook connection error, attempt {attempt + 1}/{self.retry_attempts}: {e}")
            except Exception as e:
                self.logger.error(f"Webhook error, attempt {attempt + 1}/{self.retry_attempts}: {e}")

            # Wait before retry (except on last attempt)
            if attempt < self.retry_attempts - 1:
                # Exponential backoff
                delay = self.retry_delay * (2 ** attempt)
                time.sleep(delay)

        # All retries failed
        self.events_failed += 1
        self.logger.error(f"Failed to send event to webhook after {self.retry_attempts} attempts")
        return False

    def health_check(self) -> bool:
        """
        Check webhook endpoint accessibility

        Returns:
            bool: True if webhook is accessible
        """
        if not self.enabled:
            return False

        try:
            # Try a HEAD request or OPTIONS to check if endpoint is up
            response = requests.head(
                self.url,
                headers=self.headers,
                timeout=self.timeout
            )

            is_healthy = response.status_code < 500
            self.logger.debug(f"Webhook health check: {'passed' if is_healthy else 'failed'}")
            return is_healthy

        except Exception as e:
            self.logger.error(f"Webhook health check failed: {e}")
            return False

    def close(self):
        """Clean up resources"""
        self.logger.info(f"Webhook producer closed (sent={self.events_sent}, failed={self.events_failed})")

    def get_stats(self) -> Dict[str, Any]:
        """Get producer statistics"""
        return {
            'events_sent': self.events_sent,
            'events_failed': self.events_failed,
            'retry_attempts': self.retry_attempts
        }
