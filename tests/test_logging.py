import unittest
import json
from unittest.mock import MagicMock, patch
from tap_github import main, redact_sensitive_data

class TestLogging(unittest.TestCase):
    @patch('tap_github.singer.utils.parse_args')
    @patch('tap_github.logger')
    def test_masks_token_in_error_logging(self, mock_logger, mock_parse_args):
        # Mock the response and request objects
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = json.dumps({
            "token": "secret_token_123",
            "expires_at": "2025-02-05T23:40:15Z",
            "permissions": {
                "members": "read",
                "organization_projects": "read"
            }
        })

        mock_request = {
            'url': 'https://api.github.com/some/endpoint',
            'method': 'GET'
        }

        # Mock parse_args to return a valid config instead of raising an exception
        mock_parse_args.return_value = MagicMock(
            config={'start_date': '2020-01-01', 'access_token': 'dummy', 'repository': 'test/repo'},
            discover=False,
            properties=None,
            state={}
        )

        # Set up the global variables that main() will access
        with patch('tap_github.latest_response', mock_response), \
             patch('tap_github.latest_request', mock_request), \
             patch('tap_github.do_sync') as mock_do_sync:

            # Simulate an exception during sync instead
            mock_do_sync.side_effect = Exception("Test error")
            
            # Call main() which should trigger our error logging
            with self.assertRaises(SystemExit):
                main()

            # Verify the logging calls
            log_calls = mock_logger.critical.call_args_list
            
            # Find the log line containing the response data
            response_log = None
            for call in log_calls:
                if 'Response Data:' in call[0][0]:
                    response_log = call[0][0]
                    break
            
            # Assert that the token was masked
            self.assertIsNotNone(response_log)
            self.assertIn('"token": "<TOKEN>"', response_log)
            self.assertNotIn('secret_token_123', response_log)
            
            # Verify other parts of the response remained intact
            self.assertIn('2025-02-05T23:40:15Z', response_log)
            self.assertIn('members', response_log)

    @patch('tap_github.singer.utils.parse_args')
    @patch('tap_github.logger')
    def test_handles_non_json_response(self, mock_logger, mock_parse_args):
        # Similar test but with non-JSON response text
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Not a JSON response"

        mock_request = {
            'url': 'https://api.github.com/some/endpoint',
            'method': 'GET'
        }

        # Mock parse_args to return a valid config
        mock_parse_args.return_value = MagicMock(
            config={'start_date': '2020-01-01', 'access_token': 'dummy', 'repository': 'test/repo'},
            discover=False,
            properties=None,
            state={}
        )

        with patch('tap_github.latest_response', mock_response), \
             patch('tap_github.latest_request', mock_request), \
             patch('tap_github.do_sync') as mock_do_sync:

            # Simulate error during sync
            mock_do_sync.side_effect = Exception("Test error")
            
            with self.assertRaises(SystemExit):
                main()

            # Verify the non-JSON response was logged as-is
            log_calls = mock_logger.critical.call_args_list
            response_log = None
            for call in log_calls:
                if 'Response Data:' in call[0][0]:
                    response_log = call[0][0]
                    break
            
            self.assertIsNotNone(response_log)
            self.assertIn('Not a JSON response', response_log)

    def test_redact_sensitive_data(self):
        # Test JSON response with token
        json_response = json.dumps({
            "token": "secret_token_123",
            "expires_at": "2025-02-05T23:40:15Z",
            "permissions": {
                "members": "read"
            }
        })
        redacted = redact_sensitive_data(json_response)
        self.assertIn('"token": "<TOKEN>"', redacted)
        self.assertNotIn('secret_token_123', redacted)
        self.assertIn('2025-02-05T23:40:15Z', redacted)

        # Test non-JSON response
        non_json = "Not a JSON response"
        self.assertEqual(redact_sensitive_data(non_json), non_json)

        # Test malformed JSON
        malformed_json = '{"token": "secret", "bad_json"'
        self.assertEqual(redact_sensitive_data(malformed_json), malformed_json)

if __name__ == '__main__':
    unittest.main() 