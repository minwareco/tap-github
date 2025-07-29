import unittest
import tap_github.__init__ as tap_github


class TestOnboardingWorkflowSkip(unittest.TestCase):
    """Test the filter_streams_for_onboarding function"""

    def test_filters_workflow_streams_when_onboarding_incomplete(self):
        """Test that workflow streams are filtered out when onboarding is incomplete"""
        selected_streams = [
            'repositories', 'commits', 'pull_requests',
            'workflows', 'workflow_runs', 'workflow_run_jobs'
        ]
        is_onboarding_complete = False
        
        filtered_streams, filtered_count = tap_github.filter_streams_for_onboarding(
            selected_streams, is_onboarding_complete
        )
        
        # Verify workflow streams were filtered out
        self.assertNotIn('workflows', filtered_streams)
        self.assertNotIn('workflow_runs', filtered_streams)
        self.assertNotIn('workflow_run_jobs', filtered_streams)
        
        # Verify other streams remain
        self.assertIn('repositories', filtered_streams)
        self.assertIn('commits', filtered_streams)
        self.assertIn('pull_requests', filtered_streams)
        
        # Verify counts
        self.assertEqual(len(filtered_streams), 3)
        self.assertEqual(filtered_count, 3)
        self.assertEqual(set(filtered_streams), {'repositories', 'commits', 'pull_requests'})

    def test_keeps_all_streams_when_onboarding_complete(self):
        """Test that all streams are kept when onboarding is complete"""
        selected_streams = [
            'repositories', 'commits', 'pull_requests',
            'workflows', 'workflow_runs', 'workflow_run_jobs'
        ]
        is_onboarding_complete = True
        
        filtered_streams, filtered_count = tap_github.filter_streams_for_onboarding(
            selected_streams, is_onboarding_complete
        )
        
        # Verify all streams remain (should be identical to input)
        self.assertEqual(filtered_streams, selected_streams)
        self.assertEqual(len(filtered_streams), 6)
        self.assertEqual(filtered_count, 0)
        
        # Verify all workflow streams are present
        self.assertIn('workflows', filtered_streams)
        self.assertIn('workflow_runs', filtered_streams)
        self.assertIn('workflow_run_jobs', filtered_streams)

    def test_no_workflow_streams_selected(self):
        """Test behavior when no workflow streams are selected initially"""
        selected_streams = ['repositories', 'commits', 'pull_requests']
        is_onboarding_complete = False
        
        filtered_streams, filtered_count = tap_github.filter_streams_for_onboarding(
            selected_streams, is_onboarding_complete
        )
        
        # Verify no streams were filtered since none were workflow streams
        self.assertEqual(filtered_streams, selected_streams)
        self.assertEqual(len(filtered_streams), 3)
        self.assertEqual(filtered_count, 0)

    def test_only_workflow_streams_selected(self):
        """Test behavior when only workflow streams are selected"""
        selected_streams = ['workflows', 'workflow_runs', 'workflow_run_jobs']
        is_onboarding_complete = False
        
        filtered_streams, filtered_count = tap_github.filter_streams_for_onboarding(
            selected_streams, is_onboarding_complete
        )
        
        # Verify all streams were filtered out
        self.assertEqual(filtered_streams, [])
        self.assertEqual(len(filtered_streams), 0)
        self.assertEqual(filtered_count, 3)

    def test_mixed_workflow_and_non_workflow_streams(self):
        """Test with a mix of workflow and non-workflow streams"""
        selected_streams = [
            'repositories', 'workflows', 'commits', 'workflow_runs', 
            'pull_requests', 'issues', 'workflow_run_jobs', 'releases'
        ]
        is_onboarding_complete = False
        
        filtered_streams, filtered_count = tap_github.filter_streams_for_onboarding(
            selected_streams, is_onboarding_complete
        )
        
        # Verify only non-workflow streams remain
        expected_streams = ['repositories', 'commits', 'pull_requests', 'issues', 'releases']
        self.assertEqual(set(filtered_streams), set(expected_streams))
        self.assertEqual(len(filtered_streams), 5)
        self.assertEqual(filtered_count, 3)

    def test_empty_stream_list(self):
        """Test behavior with empty stream list"""
        selected_streams = []
        is_onboarding_complete = False
        
        filtered_streams, filtered_count = tap_github.filter_streams_for_onboarding(
            selected_streams, is_onboarding_complete
        )
        
        # Verify empty list returns empty list
        self.assertEqual(filtered_streams, [])
        self.assertEqual(len(filtered_streams), 0)
        self.assertEqual(filtered_count, 0)

    def test_preserves_stream_order(self):
        """Test that the order of non-workflow streams is preserved"""
        selected_streams = [
            'repositories', 'workflows', 'commits', 'workflow_runs',
            'pull_requests', 'workflow_run_jobs', 'issues'
        ]
        is_onboarding_complete = False
        
        filtered_streams, filtered_count = tap_github.filter_streams_for_onboarding(
            selected_streams, is_onboarding_complete
        )
        
        # Verify order is preserved for non-workflow streams
        expected_order = ['repositories', 'commits', 'pull_requests', 'issues']
        self.assertEqual(filtered_streams, expected_order)
        self.assertEqual(filtered_count, 3)


if __name__ == '__main__':
    unittest.main()