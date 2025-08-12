import unittest
import tap_github.__init__ as tap_github

class TestSubStreamSelection(unittest.TestCase):

    def test_pull_request_sub_streams_selected(self):
        selected_streams = ["reviews", "pull_requests"]
        self.assertIsNone(tap_github.validate_dependencies(selected_streams))

    def test_pull_request_sub_streams_not_selected(self):
        selected_streams = ["reviews", "review_comments"]
        try:
            tap_github.validate_dependencies(selected_streams)
        except tap_github.DependencyException as e:
            self.assertEqual(str(e), "Unable to extract 'reviews' data, to receive 'reviews' data, you also need to select 'pull_requests'. Unable to extract 'review_comments' data, to receive 'review_comments' data, you also need to select 'pull_requests'.")

    def test_teams_sub_streams_selected(self):
        selected_streams = ["teams", "team_members"]
        self.assertIsNone(tap_github.validate_dependencies(selected_streams))

    def test_teams_sub_streams_not_selected(self):
        selected_streams = ["team_members"]
        try:
            tap_github.validate_dependencies(selected_streams)
        except tap_github.DependencyException as e:
            self.assertEqual(str(e), "Unable to extract 'team_members' data, to receive 'team_members' data, you also need to select 'teams'.")

    def test_projects_sub_streams_selected(self):
        selected_streams = ["projects", "project_cards"]
        self.assertIsNone(tap_github.validate_dependencies(selected_streams))

    def test_projects_sub_streams_not_selected(self):
        selected_streams = ["project_columns"]
        try:
            tap_github.validate_dependencies(selected_streams)
        except tap_github.DependencyException as e:
            self.assertEqual(str(e), "Unable to extract 'project_columns' data, to receive 'project_columns' data, you also need to select 'projects'.")

    def test_mixed_streams_positive(self):
        selected_streams = ["pull_requests", "reviews", "collaborators", "team_members", "stargazers", "projects", "teams", "project_cards"]
        self.assertIsNone(tap_github.validate_dependencies(selected_streams))

    def test_mixed_streams_negative(self):
        selected_streams = ["project_columns", "issues", "teams", "team_memberships", "projects", "releases", "review_comments"]
        try:
            tap_github.validate_dependencies(selected_streams)
        except tap_github.DependencyException as e:
            self.assertEqual(str(e), "Unable to extract 'review_comments' data, to receive 'review_comments' data, you also need to select 'pull_requests'.")
    
    def test_process_globals_false_filters_sub_streams(self):
        """Test that when process_globals=False, sub-streams of global streams are also filtered out"""
        # Create a mock catalog with all streams selected
        catalog = {
            'streams': [
                {'tap_stream_id': 'teams', 'schema': {'selected': True}, 'metadata': []},
                {'tap_stream_id': 'team_members', 'schema': {'selected': True}, 'metadata': []},
                {'tap_stream_id': 'team_memberships', 'schema': {'selected': True}, 'metadata': []},
                {'tap_stream_id': 'projects', 'schema': {'selected': True}, 'metadata': []},
                {'tap_stream_id': 'project_cards', 'schema': {'selected': True}, 'metadata': []},
                {'tap_stream_id': 'project_columns', 'schema': {'selected': True}, 'metadata': []},
                {'tap_stream_id': 'issues', 'schema': {'selected': True}, 'metadata': []},
                {'tap_stream_id': 'pull_requests', 'schema': {'selected': True}, 'metadata': []},
                {'tap_stream_id': 'copilot_usage', 'schema': {'selected': True}, 'metadata': []},
            ]
        }
        
        # Test with process_globals=False
        selected_streams = tap_github.get_selected_streams(catalog, process_globals=False)
        
        # Global streams and their sub-streams should be filtered out
        self.assertNotIn('teams', selected_streams)
        self.assertNotIn('team_members', selected_streams)
        self.assertNotIn('team_memberships', selected_streams)
        self.assertNotIn('projects', selected_streams)
        self.assertNotIn('project_cards', selected_streams)
        self.assertNotIn('project_columns', selected_streams)
        self.assertNotIn('copilot_usage', selected_streams)
        
        # Non-global streams should remain
        self.assertIn('issues', selected_streams)
        self.assertIn('pull_requests', selected_streams)
        
        # Should not raise dependency exception since sub-streams are filtered too
        tap_github.validate_dependencies(selected_streams)
    
    def test_process_globals_true_keeps_all_streams(self):
        """Test that when process_globals=True, all selected streams are kept"""
        # Create a mock catalog with all streams selected
        catalog = {
            'streams': [
                {'tap_stream_id': 'teams', 'schema': {'selected': True}, 'metadata': []},
                {'tap_stream_id': 'team_members', 'schema': {'selected': True}, 'metadata': []},
                {'tap_stream_id': 'projects', 'schema': {'selected': True}, 'metadata': []},
                {'tap_stream_id': 'project_cards', 'schema': {'selected': True}, 'metadata': []},
                {'tap_stream_id': 'issues', 'schema': {'selected': True}, 'metadata': []},
            ]
        }
        
        # Test with process_globals=True (default)
        selected_streams = tap_github.get_selected_streams(catalog, process_globals=True)
        
        # All streams should be present
        self.assertIn('teams', selected_streams)
        self.assertIn('team_members', selected_streams)
        self.assertIn('projects', selected_streams)
        self.assertIn('project_cards', selected_streams)
        self.assertIn('issues', selected_streams)
        
        # Should not raise dependency exception
        tap_github.validate_dependencies(selected_streams)
