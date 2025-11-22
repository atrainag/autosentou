"""
Rate Limit Handler for AI Services
Manages rate limiting, exponential backoff, and job suspension
"""
import time
import random
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)


class RateLimitError(Exception):
    """Custom exception for rate limit errors."""
    def __init__(self, message: str, retry_after: int = 60, provider: str = "unknown"):
        super().__init__(message)
        self.retry_after = retry_after
        self.provider = provider
        self.is_rate_limit = True


class RateLimitHandler:
    """
    Centralized handler for AI rate limits across all providers.
    Implements exponential backoff and job suspension logic.
    """

    # Provider-specific rate limit configurations
    PROVIDER_LIMITS = {
        'gemini': {
            'requests_per_minute': 10,
            'min_delay': 6.0,  # seconds between requests
            'max_retries': 3,
            'suspension_threshold': 300,  # suspend if wait > 5 minutes
        },
        'openai': {
            'requests_per_minute': 3500,
            'min_delay': 0.02,
            'max_retries': 5,
            'suspension_threshold': 300,
        },
        'deepseek': {
            'requests_per_minute': 60,
            'min_delay': 1.0,
            'max_retries': 3,
            'suspension_threshold': 300,
        },
        'ollama': {
            'requests_per_minute': None,  # No limits (local)
            'min_delay': 0,
            'max_retries': 3,
            'suspension_threshold': None,
        }
    }

    def __init__(self, provider: str = 'gemini'):
        self.provider = provider.lower()
        self.config = self.PROVIDER_LIMITS.get(self.provider, self.PROVIDER_LIMITS['gemini'])
        self.last_request_time = 0
        self.consecutive_failures = 0
        self.total_requests = 0

    def get_min_delay(self) -> float:
        """Get minimum delay between requests for current provider."""
        return self.config['min_delay']

    def wait_if_needed(self):
        """
        Wait if necessary to respect rate limits.
        Called before making an API request.
        """
        min_delay = self.config['min_delay']
        if min_delay <= 0:
            return

        elapsed = time.time() - self.last_request_time
        if elapsed < min_delay:
            sleep_time = min_delay - elapsed
            logger.debug(f"Rate limit: waiting {sleep_time:.2f}s before AI call")
            time.sleep(sleep_time)

    def record_request(self):
        """Record that a request was made."""
        self.last_request_time = time.time()
        self.total_requests += 1

    def record_success(self):
        """Record successful request - reset failure counter."""
        self.consecutive_failures = 0

    def record_failure(self):
        """Record failed request."""
        self.consecutive_failures += 1

    def is_rate_limit_error(self, exception: Exception) -> Tuple[bool, int]:
        """
        Check if an exception is a rate limit error.

        Returns:
            Tuple of (is_rate_limit, retry_after_seconds)
        """
        error_str = str(exception).lower()

        # Check for common rate limit indicators
        rate_limit_indicators = [
            'rate limit',
            'rate_limit',
            'ratelimit',
            '429',
            'too many requests',
            'quota exceeded',
            'resource exhausted',
            'requests per minute',
            'rpm limit',
        ]

        is_rate_limit = any(indicator in error_str for indicator in rate_limit_indicators)

        # Try to extract retry-after time
        retry_after = 60  # Default 1 minute

        if hasattr(exception, 'response'):
            response = exception.response
            if hasattr(response, 'headers'):
                retry_after = int(response.headers.get('Retry-After', 60))
            if hasattr(response, 'status_code') and response.status_code == 429:
                is_rate_limit = True

        # Gemini-specific: often mentions time to wait
        if 'retry after' in error_str:
            import re
            match = re.search(r'(\d+)\s*(second|minute|hour)', error_str)
            if match:
                value = int(match.group(1))
                unit = match.group(2)
                if 'minute' in unit:
                    retry_after = value * 60
                elif 'hour' in unit:
                    retry_after = value * 3600
                else:
                    retry_after = value

        return is_rate_limit, retry_after

    def calculate_backoff(self, attempt: int) -> float:
        """
        Calculate exponential backoff with jitter.

        Args:
            attempt: Current retry attempt (0-indexed)

        Returns:
            Seconds to wait before retry
        """
        base_delay = self.config['min_delay'] or 1.0
        max_delay = 300  # Cap at 5 minutes

        # Exponential backoff: delay * 2^attempt
        delay = base_delay * (2 ** attempt)

        # Add jitter (random 0-25% of delay)
        jitter = delay * random.uniform(0, 0.25)

        total_delay = min(delay + jitter, max_delay)

        return total_delay

    def should_suspend_job(self, retry_after: int) -> bool:
        """
        Determine if job should be suspended based on retry time.

        Args:
            retry_after: Seconds until rate limit resets

        Returns:
            True if job should be suspended
        """
        threshold = self.config.get('suspension_threshold')
        if threshold is None:
            return False

        # Suspend if wait time exceeds threshold or too many consecutive failures
        if retry_after > threshold:
            return True

        if self.consecutive_failures >= self.config['max_retries']:
            return True

        return False

    def get_resume_time(self, retry_after: int) -> datetime:
        """
        Calculate when job should be resumed.

        Args:
            retry_after: Seconds until rate limit resets

        Returns:
            Datetime when job can resume
        """
        # Add buffer time (10% extra)
        buffer = retry_after * 0.1
        total_wait = retry_after + buffer

        return datetime.now() + timedelta(seconds=total_wait)

    def handle_error(self, exception: Exception, attempt: int = 0) -> Dict[str, Any]:
        """
        Handle an AI service error and determine action.

        Args:
            exception: The caught exception
            attempt: Current retry attempt

        Returns:
            Dict with action info:
            {
                'is_rate_limit': bool,
                'should_retry': bool,
                'should_suspend': bool,
                'wait_seconds': int,
                'resume_at': datetime or None,
                'message': str
            }
        """
        is_rate_limit, retry_after = self.is_rate_limit_error(exception)

        if not is_rate_limit:
            # Not a rate limit error - don't retry
            return {
                'is_rate_limit': False,
                'should_retry': False,
                'should_suspend': False,
                'wait_seconds': 0,
                'resume_at': None,
                'message': f"Non-rate-limit error: {str(exception)}"
            }

        self.record_failure()

        # Check if we should suspend
        should_suspend = self.should_suspend_job(retry_after)

        if should_suspend:
            resume_at = self.get_resume_time(retry_after)
            return {
                'is_rate_limit': True,
                'should_retry': False,
                'should_suspend': True,
                'wait_seconds': retry_after,
                'resume_at': resume_at,
                'message': f"Rate limit exceeded. Job will be suspended until {resume_at.strftime('%H:%M:%S')}"
            }

        # Calculate backoff for retry
        backoff = self.calculate_backoff(attempt)
        should_retry = attempt < self.config['max_retries']

        return {
            'is_rate_limit': True,
            'should_retry': should_retry,
            'should_suspend': False,
            'wait_seconds': backoff,
            'resume_at': None,
            'message': f"Rate limit hit. {'Retrying' if should_retry else 'Max retries exceeded'} after {backoff:.1f}s"
        }


# Global handler instance (will be configured per-provider)
_rate_limit_handler = None


def get_rate_limit_handler(provider: str = None) -> RateLimitHandler:
    """Get or create rate limit handler for provider."""
    global _rate_limit_handler

    if provider:
        return RateLimitHandler(provider)

    if _rate_limit_handler is None:
        # Default to gemini
        import os
        default_provider = os.getenv('AI_PROVIDER', 'gemini')
        _rate_limit_handler = RateLimitHandler(default_provider)

    return _rate_limit_handler
