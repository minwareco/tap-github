from unittest import mock
import tap_github
import unittest
import requests

class Mockresponse:
    def __init__(self, status_code, json, raise_error, headers={'X-RateLimit-Remaining': 1}, text=None, content=None):
        self.status_code = status_code
        self.raise_error = raise_error
        self.text = json
        self.headers = headers
        self.content = content if content is not None else 'github'

    def raise_for_status(self):
        if not self.raise_error:
            return self.status_code

        raise requests.HTTPError("Sample message")

    def json(self):
        return self.text

def get_response(status_code, json={}, raise_error=False, content=None):
    return Mockresponse(status_code, json, raise_error, content=content)

@mock.patch("requests.Session.request")
class TestExceptionHandling(unittest.TestCase):
    def test_zero_content_length(self, mocked_request):
        mocked_request.return_value = get_response(400, raise_error = True, content='')

        try:
            tap_github.authed_get("", "")
        except tap_github.BadRequestException as e:
            self.assertEqual(str(e), "HTTP-error-code: 400, URL: . Error: The request is missing or has a bad parameter.")

    def test_400_error(self, mocked_request):
        mocked_request.return_value = get_response(400, raise_error = True)
        
        try:
            tap_github.authed_get("", "")
        except tap_github.BadRequestException as e:
            self.assertEqual(str(e), "HTTP-error-code: 400, URL: . Error: The request is missing or has a bad parameter.")
    
    def test_401_error(self, mocked_request):
        mocked_request.return_value = get_response(401, raise_error = True)
        
        # Set using_pat to True to avoid app token refresh logic
        original_using_pat = getattr(tap_github, 'using_pat', True)
        tap_github.using_pat = True
        
        try:
            tap_github.authed_get("", "")
        except tap_github.BadCredentialsException as e:
            self.assertEqual(str(e), "Invalid GitHub Personal Access Token (PAT). The token was rejected by GitHub.")
        finally:
            tap_github.using_pat = original_using_pat
    
    def test_403_error(self, mocked_request):
        mocked_request.return_value = get_response(403, raise_error = True)
        
        try:
            tap_github.authed_get("", "")
        except tap_github.AuthException as e:
            self.assertEqual(str(e), "HTTP-error-code: 403, URL: . Error: User doesn't have permission to access the resource.")
    
    def test_404_error(self, mocked_request):
        json = {"message": "Not Found", "documentation_url": "https:/docs.github.com/"}
        mocked_request.return_value = get_response(404, json = json, raise_error = True)

        try:
            tap_github.authed_get("", "")
        except tap_github.NotFoundException as e:
            self.assertEqual(str(e), "HTTP-error-code: 404, URL: . Error: The resource you have specified cannot be found. Please refer '{}' for more details.".format(json.get("documentation_url")))

    def test_404_error_for_teams(self, mocked_request):
        json = {"message": "Not Found", "documentation_url": "https:/docs.github.com/"}

        try:
            tap_github.raise_for_error(get_response(404, json = json, raise_error = True), "teams", "")
        except tap_github.NotFoundException as e:
            self.assertEqual(str(e), "HTTP-error-code: 404, URL: . Error: The resource you have specified cannot be found or it is a personal account repository. Please refer '{}' for more details.".format(json.get("documentation_url")))

    @mock.patch('time.sleep')
    def test_500_error(self, mocked_sleep, mocked_request):
        mocked_request.return_value = get_response(500, raise_error = True)

        try:
            tap_github.authed_get("", "")
        except tap_github.InternalServerError as e:
            self.assertIn("Internal server error 500 persisted after attempting to retry for 120 seconds", str(e))

    def test_301_error(self, mocked_request):
        mocked_request.return_value = get_response(301, raise_error = True)

        try:
            tap_github.authed_get("", "")
        except tap_github.MovedPermanentlyError as e:
            self.assertEqual(str(e), "HTTP-error-code: 301, URL: . Error: The resource you are looking for is moved to another URL.")

    def test_304_error(self, mocked_request):
        mocked_request.return_value = get_response(304, raise_error = True)

        try:
            tap_github.authed_get("", "")
        except tap_github.NotModifiedError as e:
            self.assertEqual(str(e), "HTTP-error-code: 304, URL: . Error: The requested resource has not been modified since the last time you accessed it.")

    def test_422_error(self, mocked_request):
        mocked_request.return_value = get_response(422, raise_error = True)

        try:
            tap_github.authed_get("", "")
        except tap_github.UnprocessableError as e:
            self.assertEqual(str(e), "HTTP-error-code: 422, URL: . Error: The request was not able to process right now.")

    def test_409_error(self, mocked_request):
        mocked_request.return_value = get_response(409, raise_error = True)

        try:
            tap_github.authed_get("", "")
        except tap_github.ConflictError as e:
            self.assertEqual(str(e), "HTTP-error-code: 409, URL: . Error: The request could not be completed due to a conflict with the current state of the server.")

    def test_200_success(self, mocked_request):
        json = {"key": "value"}
        mocked_request.return_value = get_response(200, json)

        resp = tap_github.authed_get("", "")
        self.assertEqual(json, resp.json())
