import tap_github.__init__ as tap_github
import unittest
from unittest import mock
import time
import requests

def api_call():
    return requests.get("https://api.github.com/rate_limit")

@mock.patch('time.sleep')
class TestRateLimit(unittest.TestCase):


    def test_rate_limt_wait(self, mocked_sleep):

        mocked_sleep.side_effect = None

        resp = api_call()
        resp.headers["X-RateLimit-Reset"] = int(round(time.time(), 0)) + 120
        resp.headers["X-RateLimit-Remaining"] = 0

        tap_github.rate_throttling(resp)

        # Check that sleep was called with approximately 120 seconds (±5% due to jitter)
        self.assertTrue(mocked_sleep.called)
        actual_sleep_time = mocked_sleep.call_args[0][0]
        expected_base = 120  # No buffer now, just the reset time
        self.assertGreaterEqual(actual_sleep_time, expected_base * 0.95)  # 114 seconds minimum
        self.assertLessEqual(actual_sleep_time, expected_base * 1.05)     # 126 seconds maximum


    def test_rate_limit_exception(self, mocked_sleep):

        mocked_sleep.side_effect = None

        resp = api_call()
        resp.headers["X-RateLimit-Reset"] = int(round(time.time(), 0)) + 601
        resp.headers["X-RateLimit-Remaining"] = 0

        try:
            tap_github.rate_throttling(resp)
        except tap_github.RateLimitExceeded as e:
            self.assertEqual(str(e), "API rate limit exceeded, please try after 601 seconds.")


    def test_rate_limit_not_exceeded(self, mocked_sleep):

        mocked_sleep.side_effect = None

        resp = api_call()
        resp.headers["X-RateLimit-Reset"] = int(round(time.time(), 0)) + 10
        resp.headers["X-RateLimit-Remaining"] = 15

        tap_github.rate_throttling(resp)

        # Should not sleep when remaining > 10
        self.assertFalse(mocked_sleep.called)
    
    def test_rate_limit_approaching(self, mocked_sleep):
        """Test proactive throttling when approaching limit"""
        mocked_sleep.side_effect = None

        resp = api_call()
        resp.headers["X-RateLimit-Reset"] = int(round(time.time(), 0)) + 10
        resp.headers["X-RateLimit-Remaining"] = 5  # Less than 10

        tap_github.rate_throttling(resp)

        # Should sleep for 1 second when approaching limit
        mocked_sleep.assert_called_with(1)
