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
        """This test is no longer relevant - rate_throttling doesn't handle retries anymore"""
        mocked_sleep.side_effect = None

        resp = api_call()
        resp.headers["X-RateLimit-Reset"] = int(round(time.time(), 0)) + 120
        resp.headers["X-RateLimit-Remaining"] = 0

        tap_github.rate_throttling(resp)

        # rate_throttling now only does proactive throttling, not reactive
        # It won't sleep for remaining=0, only for remaining<10 but >0
        self.assertFalse(mocked_sleep.called)


    def test_rate_limit_exception(self, mocked_sleep):
        """This test is no longer relevant - rate_throttling doesn't raise exceptions anymore"""
        mocked_sleep.side_effect = None

        resp = api_call()
        resp.headers["X-RateLimit-Reset"] = int(round(time.time(), 0)) + 601
        resp.headers["X-RateLimit-Remaining"] = 0

        # rate_throttling no longer raises exceptions or handles retries
        tap_github.rate_throttling(resp)
        self.assertFalse(mocked_sleep.called)  # Should not sleep for remaining=0


    def test_rate_limit_not_exceeded(self, mocked_sleep):

        mocked_sleep.side_effect = None

        resp = api_call()
        resp.headers["X-RateLimit-Reset"] = int(round(time.time(), 0)) + 10
        resp.headers["X-RateLimit-Remaining"] = 15
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
