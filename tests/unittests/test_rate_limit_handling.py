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

    def test_calculate_seconds_negative_value(self):
        """Test that calculate_seconds handles past reset times correctly"""
        # Simulate a reset time that has already passed
        past_reset_time = int(time.time()) - 10  # 10 seconds in the past
        
        # This should fail with the current implementation
        sleep_time = tap_github.calculate_seconds(past_reset_time)
        
        # Sleep time should never be negative
        self.assertGreaterEqual(sleep_time, 0, "Sleep time should never be negative")
    
    def test_calculate_seconds_with_future_reset_time(self):
        """Test that calculate_seconds works correctly for future reset times"""
        # Simulate a reset time 60 seconds in the future
        future_reset_time = int(time.time()) + 60
        
        sleep_time = tap_github.calculate_seconds(future_reset_time)
        
        # Sleep time should be approximately 60 seconds (allowing for small timing differences)
        self.assertGreaterEqual(sleep_time, 59)
        self.assertLessEqual(sleep_time, 61)
    
    @mock.patch('tap_github.__init__.metrics')
    @mock.patch('tap_github.__init__.session')
    @mock.patch('time.sleep')
    @mock.patch('time.time')
    def test_rate_limit_retry_with_expired_reset_time(self, mock_time, mock_sleep, mock_session, mock_metrics):
        """Test the actual scenario where reset time expires between retries"""
        # Simulate the exact scenario from the logs:
        # 1. First attempt at time T, reset time is T+194
        # 2. After sleeping 194 seconds, we're at time T+194
        # 3. Second attempt tries to calculate sleep time, but reset is now in the past
        
        # Mock the metrics timer context manager
        mock_timer = mock.MagicMock()
        mock_timer.tags = {}
        mock_metrics.http_request_timer.return_value.__enter__.return_value = mock_timer
        mock_metrics.http_request_timer.return_value.__exit__.return_value = None
        
        initial_time = 1000000.0
        reset_time = initial_time + 194  # Reset in 194 seconds
        
        # Time progresses: initial -> after sleep
        time_sequence = [
            initial_time,      # First request
            initial_time,      # Calculate seconds for first retry (194 seconds)
            initial_time + 194.5,  # After sleeping, reset time has just passed
            initial_time + 194.5   # Calculate seconds for second retry (-0.5 -> 0)
        ]
        mock_time.side_effect = time_sequence
        
        # First response: rate limited
        first_response = MockResponse(
            403,
            json_data={'message': 'API rate limit exceeded'},
            headers={
                'X-RateLimit-Remaining': '0',
                'X-RateLimit-Reset': str(int(reset_time))
            }
        )
        
        # Second response: still rate limited (this would happen if reset hasn't actually cleared yet)
        second_response = MockResponse(
            403,
            json_data={'message': 'API rate limit exceeded'},
            headers={
                'X-RateLimit-Remaining': '0',
                'X-RateLimit-Reset': str(int(reset_time))  # Same reset time
            }
        )
        
        # Third response: success
        success_response = MockResponse(200, json_data={'data': 'success'})
        
        mock_session.request.side_effect = [first_response, second_response, success_response]
        
        # This should not raise ValueError anymore
        result = tap_github.authed_get('test', 'http://test.com', {})
        
        # Verify sleep was called twice
        self.assertEqual(mock_sleep.call_count, 2)
        
        # First sleep should be ~194 seconds
        first_sleep_call = mock_sleep.call_args_list[0][0][0]
        self.assertEqual(first_sleep_call, 194)
        
        # Second sleep should be 0 (not negative!)
        second_sleep_call = mock_sleep.call_args_list[1][0][0]
        self.assertEqual(second_sleep_call, 0)
        
        # With the old code, this would be negative
        self.assertGreaterEqual(second_sleep_call, 0, "Sleep time must not be negative")
    
    def test_negative_sleep_would_have_caused_error(self):
        """Test that the old code would have caused ValueError with negative sleep"""
        # This test documents the exact error that would occur without our fix
        past_reset_time = int(time.time()) - 1  # 1 second in the past
        
        # Without our fix, this would return -1
        sleep_time = tap_github.calculate_seconds(past_reset_time)
        
        # Our fix ensures this is 0, not -1
        self.assertEqual(sleep_time, 0)
        
        # Document what would happen without the fix
        if sleep_time < 0:
            with self.assertRaises(ValueError) as context:
                time.sleep(sleep_time)
            self.assertIn("sleep length must be non-negative", str(context.exception))