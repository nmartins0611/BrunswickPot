"""
Enrichment Cache
LRU cache with TTL for IP enrichment data to minimize API calls
"""

from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
import logging
import threading

logger = logging.getLogger(__name__)


class EnrichmentCache:
    """Thread-safe LRU cache with TTL for enrichment data"""

    def __init__(self, max_size: int = 10000, ttl_seconds: int = 86400):
        """
        Initialize cache

        Args:
            max_size: Maximum number of entries to cache
            ttl_seconds: Time-to-live in seconds (default: 24 hours)
        """
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache = OrderedDict()
        self.lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache

        Args:
            key: Cache key (usually IP address)

        Returns:
            Cached value if exists and not expired, None otherwise
        """
        with self.lock:
            if key in self.cache:
                value, timestamp = self.cache[key]

                # Check if expired
                if datetime.now(timezone.utc) - timestamp < timedelta(seconds=self.ttl_seconds):
                    # Move to end (mark as recently used)
                    self.cache.move_to_end(key)
                    self.hits += 1
                    logger.debug(f"Cache hit for {key}")
                    return value
                else:
                    # Expired, remove from cache
                    del self.cache[key]
                    logger.debug(f"Cache expired for {key}")

            self.misses += 1
            logger.debug(f"Cache miss for {key}")
            return None

    def set(self, key: str, value: Any) -> None:
        """
        Set value in cache

        Args:
            key: Cache key (usually IP address)
            value: Value to cache
        """
        with self.lock:
            # Remove if already exists
            if key in self.cache:
                del self.cache[key]

            # Add to end
            self.cache[key] = (value, datetime.now(timezone.utc))

            # Evict oldest if over max_size
            if len(self.cache) > self.max_size:
                evicted_key = next(iter(self.cache))
                del self.cache[evicted_key]
                logger.debug(f"Cache evicted oldest entry: {evicted_key}")

    def clear(self) -> None:
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0
            logger.info("Cache cleared")

    def get_stats(self) -> dict:
        """Get cache statistics"""
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0

            return {
                'size': len(self.cache),
                'max_size': self.max_size,
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': f"{hit_rate:.2f}%",
                'ttl_seconds': self.ttl_seconds
            }

    def __len__(self) -> int:
        """Return number of cached entries"""
        with self.lock:
            return len(self.cache)
