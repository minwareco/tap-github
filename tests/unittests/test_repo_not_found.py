import unittest
from unittest import mock
from minware_singer_utils import GitLocalRepoNotFoundException
import tap_github


class TestRepoNotFoundHandling(unittest.TestCase):
    """Test that GitLocalRepoNotFoundException is caught and skipped in do_sync."""

    def _make_catalog(self, stream_ids):
        """Build a minimal catalog with the given stream IDs selected."""
        streams = []
        for sid in stream_ids:
            streams.append(
                {
                    "tap_stream_id": sid,
                    "schema": {},
                    "key_properties": ["id"],
                    "metadata": [{"breadcrumb": [], "metadata": {"selected": True}}],
                }
            )
        return {"streams": streams}

    @mock.patch("tap_github.set_auth_headers", return_value="fake-token")
    @mock.patch("tap_github.get_repo_metadata")
    @mock.patch("tap_github.GitLocal")
    @mock.patch("tap_github.get_selected_streams", return_value=["repositories"])
    @mock.patch("tap_github.validate_dependencies")
    @mock.patch("singer.write_state")
    @mock.patch.dict(
        tap_github.SYNC_FUNCTIONS, {"repositories": mock.MagicMock(return_value={})}
    )
    def test_skips_repo_when_not_found_on_clone(
        self,
        mock_write_state,
        mock_validate,
        mock_get_selected,
        mock_git_local_cls,
        mock_get_repo_metadata,
        mock_set_auth,
    ):
        """When GitLocal() raises GitLocalRepoNotFoundException, the repo is
        skipped and sync continues to the next repo."""
        mock_git_local_cls.side_effect = [
            GitLocalRepoNotFoundException("repo not found"),
            mock.MagicMock(),  # second repo succeeds
        ]

        config = {
            "repository": "org/missing-repo org/good-repo",
            "access_token": "token",
            "start_date": "2024-01-01",
        }
        catalog = self._make_catalog(["repositories"])

        # Should not raise — the missing repo is skipped
        tap_github.do_sync(config, {}, catalog)

        # GitLocal was called for both repos
        self.assertEqual(mock_git_local_cls.call_count, 2)

    @mock.patch("tap_github.set_auth_headers", return_value="fake-token")
    @mock.patch("tap_github.get_repo_metadata")
    @mock.patch("tap_github.GitLocal")
    @mock.patch("tap_github.get_selected_streams", return_value=["repositories"])
    @mock.patch("tap_github.validate_dependencies")
    @mock.patch("singer.write_state")
    def test_state_not_written_for_missing_repo(
        self,
        mock_write_state,
        mock_validate,
        mock_get_selected,
        mock_git_local_cls,
        mock_get_repo_metadata,
        mock_set_auth,
    ):
        """State should not be written for a repo that was skipped."""
        mock_git_local_cls.side_effect = GitLocalRepoNotFoundException("repo not found")

        config = {
            "repository": "org/missing-repo",
            "access_token": "token",
            "start_date": "2024-01-01",
        }
        catalog = self._make_catalog(["repositories"])

        tap_github.do_sync(config, {}, catalog)

        mock_write_state.assert_not_called()

    @mock.patch("tap_github.set_auth_headers", return_value="fake-token")
    @mock.patch("tap_github.get_repo_metadata")
    @mock.patch("tap_github.GitLocal")
    @mock.patch("tap_github.get_selected_streams", return_value=["repositories"])
    @mock.patch("tap_github.validate_dependencies")
    @mock.patch("singer.write_state")
    def test_other_gitlocal_exceptions_still_raise(
        self,
        mock_write_state,
        mock_validate,
        mock_get_selected,
        mock_git_local_cls,
        mock_get_repo_metadata,
        mock_set_auth,
    ):
        """A generic GitLocalException (not repo-not-found) should still propagate."""
        from minware_singer_utils import GitLocalException

        mock_git_local_cls.side_effect = GitLocalException("network timeout")

        config = {
            "repository": "org/some-repo",
            "access_token": "token",
            "start_date": "2024-01-01",
        }
        catalog = self._make_catalog(["repositories"])

        with self.assertRaises(GitLocalException):
            tap_github.do_sync(config, {}, catalog)


if __name__ == "__main__":
    unittest.main()
