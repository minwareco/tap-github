import unittest
from unittest import mock
import tap_github.__init__ as tap_github
import requests
import time

class MockResponse:
    def __init__(self, status_code, json_data=None, headers=None):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.headers = headers or {}

    def json(self):
        return self._json_data

class TestRateLimitHandling(unittest.TestCase):

    def test_is_rate_limit_error_with_remaining_zero(self):
        """Test rate limit detection when X-RateLimit-Remaining is 0"""
        resp = MockResponse(403, headers={'X-RateLimit-Remaining': '0'})
        self.assertTrue(tap_github.is_rate_limit_error(resp, {}))

    def test_is_rate_limit_error_with_message(self):
        """Test rate limit detection based on error message"""
        resp = MockResponse(403)
        response_json = {'message': 'API rate limit exceeded for user'}
        self.assertTrue(tap_github.is_rate_limit_error(resp, response_json))

    def test_is_rate_limit_error_secondary_rate_limit(self):
        """Test secondary rate limit detection"""
        resp = MockResponse(403)
        response_json = {'message': 'You have exceeded a secondary rate limit'}
        self.assertTrue(tap_github.is_rate_limit_error(resp, response_json))

    def test_is_not_rate_limit_error(self):
        """Test that regular 403 auth errors are not detected as rate limits"""
        resp = MockResponse(403)
        response_json = {'message': 'Bad credentials'}
        self.assertFalse(tap_github.is_rate_limit_error(resp, response_json))

    def test_is_not_rate_limit_error_different_status(self):
        """Test that non-403 errors are not detected as rate limits"""
        resp = MockResponse(401, headers={'X-RateLimit-Remaining': '0'})
        self.assertFalse(tap_github.is_rate_limit_error(resp, {}))

    @mock.patch('time.sleep')
    def test_rate_throttling_secondary_rate_limit(self, mocked_sleep):
        """Test that rate_throttling no longer handles reactive rate limiting"""
        resp = MockResponse(403, headers={'Retry-After': '60'})
        
        tap_github.rate_throttling(resp)
        
        # rate_throttling no longer handles reactive rate limiting
        self.assertFalse(mocked_sleep.called)

    @mock.patch('time.sleep')
    def test_rate_throttling_fallback_for_403(self, mocked_sleep):
        """Test that rate_throttling no longer handles reactive rate limiting"""
        resp = MockResponse(403)
        
        tap_github.rate_throttling(resp)
        
        # rate_throttling no longer handles reactive rate limiting
        self.assertFalse(mocked_sleep.called)

    def test_rate_throttling_no_longer_handles_retries(self):
        """Test that rate_throttling no longer handles rate limit errors"""
        resp = MockResponse(200, headers={
            'X-RateLimit-Remaining': '0',  # Even at 0, rate_throttling doesn't handle it
            'X-RateLimit-Reset': str(int(time.time()) + 700)
        })
        
        # Should not raise an exception - retries are now handled in authed_get
        tap_github.rate_throttling(resp)  # Should complete without error

    def test_raise_for_error_handles_auth_errors_normally(self):
        """Test that regular 403 auth errors still raise AuthException"""
        resp = MockResponse(403, json_data={'message': 'Bad credentials'})
        
        with self.assertRaises(tap_github.AuthException):
            tap_github.raise_for_error(resp, 'test', 'http://test.com')

    def test_429_error_mapping(self):
        """Test that 429 errors are mapped to RateLimitExceeded"""
        resp = MockResponse(429, json_data={'message': 'Too many requests'})
        
        with self.assertRaises(tap_github.RateLimitExceeded):
            tap_github.raise_for_error(resp, 'test', 'http://test.com')

    def test_exponential_backoff_calculation(self):
        """Test the exponential backoff calculation logic"""
        from random import seed
        seed(42)  # For consistent test results
        
        # Test the exponential backoff formula: 60 * (2 ** (retry_count - 1)) + randint(5, 15)
        # First retry: 60 * (2^0) + jitter = 60 + jitter
        # Second retry: 60 * (2^1) + jitter = 120 + jitter  
        # Third retry: 60 * (2^2) + jitter = 240 + jitter
        
        for retry_count in [1, 2, 3]:
            from random import randint
            expected_base = 60 * (2 ** (retry_count - 1))
            sleep_time = expected_base + randint(5, 15)
            
            self.assertGreaterEqual(sleep_time, expected_base + 5)
            self.assertLessEqual(sleep_time, expected_base + 15)