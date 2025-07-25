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
        """Test rate throttling handles Retry-After header"""
        resp = MockResponse(403, headers={'Retry-After': '60'})
        
        tap_github.rate_throttling(resp)
        
        self.assertTrue(mocked_sleep.called)
        actual_sleep_time = mocked_sleep.call_args[0][0]
        # Should be exactly 60 seconds (no jitter for Retry-After)
        self.assertEqual(actual_sleep_time, 60)

    @mock.patch('time.sleep')
    def test_rate_throttling_fallback_for_403(self, mocked_sleep):
        """Test rate throttling fallback for 403 without specific headers"""
        resp = MockResponse(403)
        
        tap_github.rate_throttling(resp)
        
        self.assertTrue(mocked_sleep.called)
        actual_sleep_time = mocked_sleep.call_args[0][0]
        # Should be exactly 60 seconds minimum (no headers)
        self.assertEqual(actual_sleep_time, 60)

    def test_rate_throttling_raises_on_long_wait(self):
        """Test that very long rate limits raise an exception"""
        resp = MockResponse(200, headers={
            'X-RateLimit-Remaining': '0',  # Must be 0 to trigger rate limit
            'X-RateLimit-Reset': str(int(time.time()) + 700)  # 700 seconds = > 10 minutes
        })
        
        with self.assertRaises(tap_github.RateLimitExceeded):
            tap_github.rate_throttling(resp)

    @mock.patch('tap_github.__init__.rate_throttling')
    def test_raise_for_error_detects_rate_limit(self, mocked_rate_throttling):
        """Test that raise_for_error correctly identifies and handles rate limits"""
        resp = MockResponse(403, 
                          json_data={'message': 'API rate limit exceeded'},
                          headers={'X-RateLimit-Remaining': '0'})
        
        # Should not raise an exception, should call rate_throttling instead
        tap_github.raise_for_error(resp, 'test', 'http://test.com')
        
        mocked_rate_throttling.assert_called_once_with(resp)

    def test_raise_for_error_handles_auth_errors_normally(self):
        """Test that regular 403 auth errors still raise AuthException"""
        resp = MockResponse(403, json_data={'message': 'Bad credentials'})
        
        with self.assertRaises(tap_github.AuthException):
            tap_github.raise_for_error(resp, 'test', 'http://test.com')

    @mock.patch('time.sleep')
    def test_rate_throttling_handles_429(self, mocked_sleep):
        """Test that 429 errors are handled by rate_throttling"""
        resp = MockResponse(429, headers={'Retry-After': '45'})
        
        tap_github.rate_throttling(resp)
        
        self.assertTrue(mocked_sleep.called)
        actual_sleep_time = mocked_sleep.call_args[0][0]
        # Should be exactly 45 seconds (no jitter for Retry-After)
        self.assertEqual(actual_sleep_time, 45)

    @mock.patch('time.sleep')
    def test_rate_throttling_429_fallback(self, mocked_sleep):
        """Test 429 fallback when no Retry-After header"""
        resp = MockResponse(429)
        
        tap_github.rate_throttling(resp)
        
        self.assertTrue(mocked_sleep.called)
        actual_sleep_time = mocked_sleep.call_args[0][0]
        # Should be exactly 60 seconds minimum (no headers)
        self.assertEqual(actual_sleep_time, 60)

    def test_429_error_mapping(self):
        """Test that 429 errors are mapped to RateLimitExceeded"""
        resp = MockResponse(429, json_data={'message': 'Too many requests'})
        
        with self.assertRaises(tap_github.RateLimitExceeded):
            tap_github.raise_for_error(resp, 'test', 'http://test.com')

    @mock.patch('time.sleep')
    def test_exponential_backoff_secondary_rate_limit(self, mocked_sleep):
        """Test exponential backoff for secondary rate limits"""
        resp = MockResponse(403, 
                          json_data={'message': 'You have exceeded a secondary rate limit'},
                          headers={'X-RateLimit-Remaining': '0'})
        
        # First retry (0) = 60 seconds
        tap_github.rate_throttling(resp, retry_count=0)
        self.assertGreaterEqual(mocked_sleep.call_args[0][0], 54)  # 60 * 0.9
        self.assertLessEqual(mocked_sleep.call_args[0][0], 66)     # 60 * 1.1
        
        # Second retry (1) = 120 seconds
        tap_github.rate_throttling(resp, retry_count=1)
        self.assertGreaterEqual(mocked_sleep.call_args[0][0], 108)  # 120 * 0.9
        self.assertLessEqual(mocked_sleep.call_args[0][0], 132)     # 120 * 1.1
        
        # Third retry (2) = 240 seconds
        tap_github.rate_throttling(resp, retry_count=2)
        self.assertGreaterEqual(mocked_sleep.call_args[0][0], 216)  # 240 * 0.9
        self.assertLessEqual(mocked_sleep.call_args[0][0], 264)     # 240 * 1.1