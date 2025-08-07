import unittest
from unittest.mock import patch, MagicMock
import tap_github

class TestProcessGlobalsOnly(unittest.TestCase):
    """Test the process_globals functionality with different values"""

    @patch('tap_github.GitLocal')
    @patch('tap_github.translate_state')
    @patch('tap_github.logger')
    @patch('tap_github.write_schema')
    @patch('tap_github.get_selected_streams')
    @patch('tap_github.validate_dependencies')
    @patch('tap_github.filter_streams_for_onboarding')
    @patch('tap_github.set_auth_headers')
    def test_process_globals_only_skips_non_global_streams(self, mock_set_auth, mock_filter, 
                                                          mock_validate, mock_get_selected, 
                                                          mock_write_schema, mock_logger,
                                                          mock_translate_state, mock_gitlocal):
        """Test that when process_globals='only', only global streams are processed"""
        
        # Setup mocks - when process_globals='only', get_selected_streams should only return global streams
        mock_get_selected.return_value = ['teams', 'copilot_usage']
        mock_validate.return_value = None
        mock_filter.return_value = (['teams', 'copilot_usage'], 0)
        mock_set_auth.return_value = 'fake_token'
        mock_translate_state.return_value = {}
        mock_gitlocal.return_value = MagicMock()
        
        # Create test config with process_globals='only'
        config = {
            'repository': 'testorg/__minware_globals__',
            'process_globals': 'only',
            'access_token': 'fake_token',
            'start_date': '2024-01-01T00:00:00Z',
            'is_onboarding_complete': True
        }
        
        # Create test catalog with global streams only (since get_selected_streams will filter)
        catalog = {
            'streams': [
                {
                    'tap_stream_id': 'teams',
                    'schema': {'type': 'object'},
                    'key_properties': ['id'],
                    'metadata': []
                },
                {
                    'tap_stream_id': 'copilot_usage',
                    'schema': {'type': 'object'},
                    'key_properties': ['date'],
                    'metadata': []
                }
            ]
        }
        
        state = {}
        
        # Mock the sync functions to track what gets called
        sync_calls = []
        
        def mock_sync_func(stream_id):
            def sync(*args, **kwargs):
                sync_calls.append(stream_id)
                return state
            return sync
        
        # Override SYNC_FUNCTIONS with our mocks
        original_sync_functions = tap_github.SYNC_FUNCTIONS.copy()
        tap_github.SYNC_FUNCTIONS = {
            'teams': mock_sync_func('teams'),
            'copilot_usage': mock_sync_func('copilot_usage')
        }
        
        try:
            # Run do_sync
            tap_github.do_sync(config, state, catalog)
            
            # Verify only global streams were synced
            self.assertIn('teams', sync_calls)
            self.assertIn('copilot_usage', sync_calls)
            
            # Verify get_selected_streams was called with process_globals='only'
            mock_get_selected.assert_called_once_with(catalog, 'only')
            
            # Verify the logger was called for globals-only processing
            mock_logger.info.assert_any_call("Processing globals-only dummy repository")
            
        finally:
            # Restore original sync functions
            tap_github.SYNC_FUNCTIONS = original_sync_functions

    def test_get_selected_streams_filtering(self):
        """Test that get_selected_streams filters streams correctly based on process_globals"""
        
        # Create a test catalog with mixed streams
        catalog = {
            'streams': [
                {'tap_stream_id': 'repositories', 'schema': {'selected': True}, 'metadata': []},
                {'tap_stream_id': 'teams', 'schema': {'selected': True}, 'metadata': []},
                {'tap_stream_id': 'commits', 'schema': {'selected': True}, 'metadata': []},
                {'tap_stream_id': 'copilot_usage', 'schema': {'selected': True}, 'metadata': []},
                {'tap_stream_id': 'issues', 'schema': {'selected': True}, 'metadata': []},
                {'tap_stream_id': 'projects', 'schema': {'selected': True}, 'metadata': []},
            ]
        }
        
        # Test process_globals = True (should return all streams)
        result = tap_github.get_selected_streams(catalog, True)
        expected = ['repositories', 'teams', 'commits', 'copilot_usage', 'issues', 'projects']
        self.assertEqual(sorted(result), sorted(expected))
        
        # Test process_globals = False (should filter out global streams)
        result = tap_github.get_selected_streams(catalog, False)
        expected = ['repositories', 'commits', 'issues']  # non-global streams only
        self.assertEqual(sorted(result), sorted(expected))
        
        # Test process_globals = 'only' (should return only global streams)
        result = tap_github.get_selected_streams(catalog, 'only')
        expected = ['teams', 'copilot_usage', 'projects']  # global streams only
        self.assertEqual(sorted(result), sorted(expected))
    

if __name__ == '__main__':
    unittest.main()