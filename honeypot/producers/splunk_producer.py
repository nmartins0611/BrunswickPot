"""
Splunk HEC Producer
Sends events to Splunk via HTTP Event Collector (HEC)
"""

from typing import Dict, Any, List
import logging
import requests
import json
import time
from queue import Queue
from threading import Thread, Event
from datetime import datetime

from .base import BaseProducer, ProducerConnectionError, ProducerSendError

logger = logging.getLogger(__name__)


class SplunkHECProducer(BaseProducer):
    """Producer for sending events to Splunk via HEC"""

    def __init__(self, config: Dict[str, Any], honeypot_id: str = "honeypot-01"):
        """
        Initialize Splunk HEC producer

        Args:
            config: Splunk configuration dictionary
            honeypot_id: Identifier for this honeypot instance
        """
        super().__init__(config, producer_name="SplunkHECProducer")

        self.honeypot_id = honeypot_id
        self.hec_url = config.get('hec_url')
        self.hec_token = config.get('hec_token')
        self.index = config.get('index', 'honeypot_events')
        self.source = config.get('source', 'honeypot')
        self.sourcetype = config.get('sourcetype', 'honeypot:json')
        self.verify_ssl = config.get('verify_ssl', True)
        self.batch_size = config.get('batch_size', 10)
        self.flush_interval = config.get('flush_interval', 5)  # seconds

        # Batching
        self.batch_queue = Queue()
        self.batch_thread = None
        self.stop_event = Event()

        # Statistics
        self.events_sent = 0
        self.events_failed = 0

        if self.enabled:
            if not self.hec_url or not self.hec_token:
                self.logger.error("Splunk HEC URL and token are required")
                self.enabled = False
            else:
                # Start batch processing thread
                self._start_batch_thread()
                self.logger.info(f"Splunk HEC producer initialized (batch_size={self.batch_size})")

    def send(self, event: Dict[str, Any]) -> bool:
        """
        Queue event for batch sending to Splunk

        Args:
            event: Event dictionary to send

        Returns:
            bool: True if queued successfully
        """
        if not self.enabled:
            return False

        try:
            # Convert to Splunk HEC format
            hec_event = self._format_event(event)

            # Add to batch queue
            self.batch_queue.put(hec_event)

            return True

        except Exception as e:
            self.logger.error(f"Failed to queue event for Splunk: {e}")
            return False

    def _format_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format event for Splunk HEC

        Args:
            event: Original event dictionary

        Returns:
            Splunk HEC formatted event
        """
        # Extract timestamp
        timestamp_str = event.get('timestamp')
        if timestamp_str:
            try:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                timestamp = dt.timestamp()
            except:
                timestamp = time.time()
        else:
            timestamp = time.time()

        # Create HEC event
        hec_event = {
            'time': timestamp,
            'host': self.honeypot_id,
            'source': self.source,
            'sourcetype': self.sourcetype,
            'index': self.index,
            'event': event
        }

        return hec_event

    def _start_batch_thread(self):
        """Start background thread for batch processing"""
        self.batch_thread = Thread(target=self._batch_worker, daemon=True)
        self.batch_thread.start()
        self.logger.debug("Batch processing thread started")

    def _batch_worker(self):
        """Background worker that sends events in batches"""
        batch = []
        last_flush = time.time()

        while not self.stop_event.is_set():
            try:
                # Try to get an event from queue (with timeout)
                try:
                    event = self.batch_queue.get(timeout=1)
                    batch.append(event)
                except:
                    pass  # Timeout, no event available

                # Send batch if:
                # 1. Batch size reached, or
                # 2. Flush interval elapsed and batch not empty
                current_time = time.time()
                should_flush = (
                    len(batch) >= self.batch_size or
                    (len(batch) > 0 and (current_time - last_flush) >= self.flush_interval)
                )

                if should_flush:
                    self._send_batch(batch)
                    batch = []
                    last_flush = current_time

            except Exception as e:
                self.logger.error(f"Batch worker error: {e}")

        # Flush remaining events on shutdown
        if batch:
            self._send_batch(batch)

    def _send_batch(self, batch: List[Dict[str, Any]]):
        """
        Send batch of events to Splunk HEC

        Args:
            batch: List of HEC formatted events
        """
        if not batch:
            return

        try:
            headers = {
                'Authorization': f'Splunk {self.hec_token}',
                'Content-Type': 'application/json'
            }

            # Splunk HEC accepts newline-delimited JSON
            payload = '\n'.join([json.dumps(event) for event in batch])

            response = requests.post(
                self.hec_url,
                headers=headers,
                data=payload,
                verify=self.verify_ssl,
                timeout=10
            )

            if response.status_code == 200:
                self.events_sent += len(batch)
                self.logger.debug(f"Sent batch of {len(batch)} events to Splunk")
            else:
                self.events_failed += len(batch)
                self.logger.error(f"Splunk HEC returned {response.status_code}: {response.text}")

        except requests.exceptions.Timeout:
            self.events_failed += len(batch)
            self.logger.error(f"Timeout sending batch to Splunk")
        except Exception as e:
            self.events_failed += len(batch)
            self.logger.error(f"Failed to send batch to Splunk: {e}")

    def health_check(self) -> bool:
        """
        Check Splunk HEC endpoint health

        Returns:
            bool: True if endpoint is accessible
        """
        if not self.enabled:
            return False

        try:
            headers = {
                'Authorization': f'Splunk {self.hec_token}'
            }

            # Use health check endpoint
            health_url = self.hec_url.replace('/services/collector', '/services/collector/health')

            response = requests.get(
                health_url,
                headers=headers,
                verify=self.verify_ssl,
                timeout=5
            )

            is_healthy = response.status_code == 200
            self.logger.debug(f"Splunk health check: {'passed' if is_healthy else 'failed'}")
            return is_healthy

        except Exception as e:
            self.logger.error(f"Splunk health check failed: {e}")
            return False

    def close(self):
        """Close producer and flush pending events"""
        if self.batch_thread:
            self.logger.info("Flushing pending Splunk events...")
            self.stop_event.set()
            self.batch_thread.join(timeout=10)
            self.logger.info(f"Splunk producer closed (sent={self.events_sent}, failed={self.events_failed})")

    def get_stats(self) -> Dict[str, Any]:
        """Get producer statistics"""
        return {
            'events_sent': self.events_sent,
            'events_failed': self.events_failed,
            'queue_size': self.batch_queue.qsize(),
            'batch_size': self.batch_size
        }
