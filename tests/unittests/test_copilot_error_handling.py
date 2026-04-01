from unittest import mock
import tap_github
import unittest


class TestCopilotErrorHandling(unittest.TestCase):
    """Tests that copilot_usage stream gracefully handles errors without crashing the sync."""

    def _make_state(self):
        return {}

    def _make_mdata(self):
        return [{'breadcrumb': [], 'metadata': {}}]

    def _make_schema(self):
        return {
            'type': 'object',
            'properties': {
                'org': {'type': ['null', 'string']},
                'team_slug': {'type': ['null', 'string']},
                'date': {'type': ['null', 'string']},
                'record': {'type': ['null', 'string']},
            }
        }

    @mock.patch('tap_github.getAccountType', return_value='ORGANIZATION')
    @mock.patch('tap_github.authed_get_all_pages')
    def test_org_level_gone_error_skips_gracefully(self, mock_get_all_pages, mock_account_type):
        """410 Gone at org level should skip the stream, not crash."""
        mock_get_all_pages.side_effect = tap_github.GoneError('410 Gone', mock.Mock())

        state = self._make_state()
        result = tap_github.get_all_copilot_usage(
            self._make_schema(), 'test-org/test-repo', state, self._make_mdata(), '2025-01-01'
        )
        self.assertEqual(result, state)

    @mock.patch('tap_github.getAccountType', return_value='ORGANIZATION')
    @mock.patch('tap_github.authed_get_all_pages')
    def test_org_level_internal_server_error_skips_gracefully(self, mock_get_all_pages, mock_account_type):
        """500 error at org level should skip the stream, not crash."""
        mock_get_all_pages.side_effect = tap_github.InternalServerError('500 Internal Server Error', mock.Mock())

        state = self._make_state()
        result = tap_github.get_all_copilot_usage(
            self._make_schema(), 'test-org/test-repo', state, self._make_mdata(), '2025-01-01'
        )
        self.assertEqual(result, state)

    @mock.patch('tap_github.getAccountType', return_value='ORGANIZATION')
    @mock.patch('tap_github.authed_get_all_pages')
    def test_org_level_generic_exception_skips_gracefully(self, mock_get_all_pages, mock_account_type):
        """Any unexpected exception at org level should skip the stream, not crash."""
        mock_get_all_pages.side_effect = Exception('Something completely unexpected')

        state = self._make_state()
        result = tap_github.get_all_copilot_usage(
            self._make_schema(), 'test-org/test-repo', state, self._make_mdata(), '2025-01-01'
        )
        self.assertEqual(result, state)

    @mock.patch('tap_github.getAccountType', return_value='ORGANIZATION')
    @mock.patch('tap_github.authed_get_all_pages')
    def test_team_level_error_does_not_block_other_teams(self, mock_get_all_pages, mock_account_type):
        """A team-level error should not prevent other teams from being fetched."""
        org_metrics_response = mock.Mock()
        org_metrics_response.json.return_value = [
            {'date': '2025-01-01', 'total_active_users': 5}
        ]
        org_metrics_response.links = {}

        teams_response = mock.Mock()
        teams_response.json.return_value = [
            {'slug': 'team-a'},
            {'slug': 'team-b'},
            {'slug': 'team-c'},
        ]
        teams_response.links = {}

        team_b_response = mock.Mock()
        team_b_response.json.return_value = [
            {'date': '2025-01-01', 'total_active_users': 2}
        ]
        team_b_response.links = {}

        team_c_response = mock.Mock()
        team_c_response.json.return_value = [
            {'date': '2025-01-01', 'total_active_users': 3}
        ]
        team_c_response.links = {}

        def side_effect(source, url, headers={}):
            if '/copilot/metrics' in url and 'team' not in url:
                return iter([org_metrics_response])
            elif '/teams?' in url:
                return iter([teams_response])
            elif '/team/team-a/copilot' in url:
                raise tap_github.GoneError('410 Gone', mock.Mock())
            elif '/team/team-b/copilot' in url:
                return iter([team_b_response])
            elif '/team/team-c/copilot' in url:
                return iter([team_c_response])
            return iter([])

        mock_get_all_pages.side_effect = side_effect

        with mock.patch('singer.write_record'), \
             mock.patch('singer.write_bookmark'), \
             mock.patch('singer.Transformer') as mock_transformer:
            mock_transformer.return_value.__enter__ = mock.Mock(return_value=mock.Mock(
                transform=mock.Mock(return_value={})
            ))
            mock_transformer.return_value.__exit__ = mock.Mock(return_value=False)

            state = self._make_state()
            result = tap_github.get_all_copilot_usage(
                self._make_schema(), 'test-org/test-repo', state, self._make_mdata(), '2025-01-01'
            )
            self.assertEqual(result, state)

        # Verify all three team URLs were attempted (team-a fails, team-b and team-c succeed)
        team_calls = [
            call for call in mock_get_all_pages.call_args_list
            if '/team/' in str(call) and '/copilot' in str(call)
        ]
        self.assertEqual(len(team_calls), 3)

    @mock.patch('tap_github.getAccountType', return_value='ORGANIZATION')
    @mock.patch('tap_github.authed_get_all_pages')
    def test_auth_exception_skips_gracefully(self, mock_get_all_pages, mock_account_type):
        """403 auth error should skip the stream, not crash."""
        mock_get_all_pages.side_effect = tap_github.AuthException('403 Forbidden', mock.Mock())

        state = self._make_state()
        result = tap_github.get_all_copilot_usage(
            self._make_schema(), 'test-org/test-repo', state, self._make_mdata(), '2025-01-01'
        )
        self.assertEqual(result, state)

    @mock.patch('tap_github.getAccountType', return_value='USER')
    def test_user_account_skips_immediately(self, mock_account_type):
        """User accounts should skip copilot metrics entirely."""
        state = self._make_state()
        result = tap_github.get_all_copilot_usage(
            self._make_schema(), 'some-user/some-repo', state, self._make_mdata(), '2025-01-01'
        )
        self.assertEqual(result, state)
