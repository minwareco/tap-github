import argparse
import os
import json
import collections
import sys
import time
import traceback
import requests
import singer
import singer.bookmarks as bookmarks
import singer.metrics as metrics
import base64
import difflib
import asyncio
import psutil
import gc
import debugpy
import jwt
import io
import zipfile
import xml.etree.ElementTree as ET
import urllib.parse
from .utils import camel_to_snake_dict

DEBUG = False
if DEBUG:
    debugpy.listen(("0.0.0.0", 9229))
    debugpy.wait_for_client()
    breakpoint()

from minware_singer_utils import GitLocal, SecureLogger

from singer import metadata

# Will be set by config as global
api_url = ''
graphql_url = ''

session = requests.Session()
logger = SecureLogger(singer.get_logger())

using_pat = False

REQUIRED_CONFIG_KEYS = ['start_date', 'access_token', 'repository']

KEY_PROPERTIES = {
    'branches': ['repo_name'],
    'code_coverage': ['id'],
    'commits': ['id'],
    'commit_files': ['id'],
    'comments': ['id'],
    'deployments': ['id'],
    'deployment_statuses': ['id'],
    'issues': ['id'],
    'assignees': ['id'],
    'collaborators': ['id'],
    'pull_requests':['id'],
    'stargazers': ['user_id'],
    'releases': ['id'],
    'reviews': ['id'],
    'review_comments': ['id'],
    'events': ['id'],
    'issue_events': ['id'],
    'issue_labels': ['id'],
    'issue_milestones': ['id'],
    'commit_comments': ['id'],
    'projects': ['id'],
    'projects_v2': ['id'],
    'projects_v2_issues': ['id'],
    'project_columns': ['id'],
    'project_cards': ['id'],
    'refs': ['id'],
    'repos': ['id'],
    'teams': ['id'],
    'team_members': ['id'],
    'team_memberships': ['url'],
    'workflows': ['id'],
    'workflow_runs': ['id'],
    'workflow_run_jobs': ['id']
}

class GithubException(Exception):
    server_response = None
    def __init__(self, message, server_response=None):
        super().__init__(message)
        self.server_response = server_response

class BadCredentialsException(GithubException):
    pass

class AuthException(GithubException):
    pass

class NotFoundException(GithubException):
    pass

class BadRequestException(GithubException):
    pass

class InternalServerError(GithubException):
    pass

class UnprocessableError(GithubException):
    pass

class NotModifiedError(GithubException):
    pass

class MovedPermanentlyError(GithubException):
    pass

class ConflictError(GithubException):
    pass

class GoneError(GithubException):
    pass

class RateLimitExceeded(GithubException):
    pass

class UnavailableForLegalReasonsError(GithubException):
    pass

ERROR_CODE_EXCEPTION_MAPPING = {
    301: {
        "raise_exception": MovedPermanentlyError,
        "message": "The resource you are looking for is moved to another URL."
    },
    304: {
        "raise_exception": NotModifiedError,
        "message": "The requested resource has not been modified since the last time you accessed it."
    },
    400:{
        "raise_exception": BadRequestException,
        "message": "The request is missing or has a bad parameter."
    },
    401: {
        "raise_exception": BadCredentialsException,
        "message": "Invalid authorization credentials."
    },
    403: {
        "raise_exception": AuthException,
        "message": "User doesn't have permission to access the resource."
    },
    404: {
        "raise_exception": NotFoundException,
        "message": "The resource you have specified cannot be found"
    },
    409: {
        "raise_exception": ConflictError,
        "message": "The request could not be completed due to a conflict with the current state of the server."
    },
    410: {
        "raise_exception": GoneError,
        "message": "The target resource is no longer available at the origin server and that this condition is likely to be permanent."
    },
    422: {
        "raise_exception": UnprocessableError,
        "message": "The request was not able to process right now."
    },
    451: {
        "raise_exception": UnavailableForLegalReasonsError,
        "message": "The requested resource is unavailable for legal reasons"
    },
    500: {
        "raise_exception": InternalServerError,
        "message": "An error has occurred at Github's end."
    }
}

org_cache_flags = {}
process_globals = True
code_coverage_artifact_name = 'test-coverage'

def has_org_cache(org, stream_name):
    global org_cache_flags
    key = '{}.{}'.format(org, stream_name)
    return org_cache_flags.get(key) == True

def set_has_org_cache(org, stream_name, value = True):
    global org_cache_flags
    key = '{}.{}'.format(org, stream_name)
    org_cache_flags[key] = value

def utf8_hook(data, typ, schema):
    if typ != 'string':
        return data

    # Don't need to handle these either
    if schema.get('format') == 'date_time' or schema.get('format') == 'singer.decimal':
        return data

    # Without this, the string 'None' gets passed through
    if data is None:
        return data

    try:
        # Replace null bytes to make valid utf-8 text
        decodedStr = bytes(str(data), 'utf-8').decode('utf-8', 'ignore').replace('\u0000','')
        return decodedStr
    except UnicodeDecodeError:
        return None

def translate_state(state, catalog, repositories):
    '''
    This tap used to only support a single repository, in which case the
    state took the shape of:
    {
      "bookmarks": {
        "commits": {
          "since": "2018-11-14T13:21:20.700360Z"
        }
      }
    }
    The tap now supports multiple repos, so this function should be called
    at the beginning of each run to ensure the state is translate to the
    new format:
    {
      "bookmarks": {
        "singer-io/tap-adwords": {
          "commits": {
            "since": "2018-11-14T13:21:20.700360Z"
          }
        }
        "singer-io/tap-salesforce": {
          "commits": {
            "since": "2018-11-14T13:21:20.700360Z"
          }
        }
      }
    }
    '''
    nested_dict = lambda: collections.defaultdict(nested_dict)
    new_state = nested_dict()

    for stream in catalog['streams']:
        stream_name = stream['tap_stream_id']
        for repo in repositories:
            if bookmarks.get_bookmark(state, repo, stream_name):
                return state
            if bookmarks.get_bookmark(state, stream_name, 'since'):
                new_state['bookmarks'][repo][stream_name]['since'] = bookmarks.get_bookmark(state, stream_name, 'since')

    return new_state


def get_bookmark(state, repo, stream_name, bookmark_key, start_date=None):
    repo_stream_dict = bookmarks.get_bookmark(state, repo, stream_name)
    if repo_stream_dict:
        return repo_stream_dict.get(bookmark_key)
    if start_date:
        return start_date
    return None

def raise_for_error(resp, source, url):
    error_code = resp.status_code
    try:
        response_json = resp.json()
    except Exception:
        response_json = {}

    if error_code == 404:
        details = ERROR_CODE_EXCEPTION_MAPPING.get(error_code).get("message")
        if source == "teams":
            details += ' or it is a personal account repository'
        message = "HTTP-error-code: 404, URL: {}. Error: {}. Please refer \'{}\' for more details." \
            .format(url, details, response_json.get("documentation_url"))
    else:
        message = "HTTP-error-code: {}, URL: {}. Error: {}".format(
            error_code, url, ERROR_CODE_EXCEPTION_MAPPING.get(error_code, {}).get("message", "Unknown Error") if response_json == {} else response_json)

    exc = ERROR_CODE_EXCEPTION_MAPPING.get(error_code, {}).get("raise_exception", GithubException)
    raise exc(message, response_json) from None

def calculate_seconds(epoch):
    current = time.time()
    return int(round((epoch - current), 0))

def rate_throttling(response):
    if response.headers.get('x-ratelimit-remaining') == None:
        return
    if int(response.headers['X-RateLimit-Remaining']) < 10:
        seconds_to_sleep = calculate_seconds(int(response.headers['X-RateLimit-Reset']))

        #if seconds_to_sleep > 600:
        #    message = "API rate limit exceeded, please try after {} seconds.".format(seconds_to_sleep)
        #    raise RateLimitExceeded(message) from None

        logger.info("API rate limit exceeded. Tap will retry the data collection after %s seconds.", seconds_to_sleep)
        time.sleep(seconds_to_sleep + 10)

# pylint: disable=dangerous-default-value
# Retry for up to two minutes, then die. It's important not to spend too long on this since some
# endpoints will return 500 when they really should return 404 and we need to skip them.
MAX_RETRY_TIME = 120
RETRY_WAIT = 15  # Wait between requests when the server is struggling

latest_response = None
latest_request = None
def authed_get(source, url, headers={}, overrideMethod='get', data=None):
    global latest_response
    global latest_request
    with metrics.http_request_timer(source) as timer:
        timer.tags['url'] = url
        timer.tags['method'] = overrideMethod
        session.headers.update(headers)
        retry_time = 0
        just_refreshed_token = False
        network_retry_count = 0
        network_max_retries = 5
        
        while True:
            try:
                latest_request = { 'method': overrideMethod, 'url': url, 'data': data}
                resp = session.request(method=overrideMethod, url=url, data=data)
                latest_response = resp
                # If there is another 401 error right after refreshing, then don't try again. Otherwise,
                # get a new installation token for the github app and try again in case there is a
                # token expiration
                if not just_refreshed_token and resp.status_code == 401:
                    if using_pat:
                        # If using a PAT and getting a 401, fail immediately rather than trying to refresh
                        raise BadCredentialsException('Invalid GitHub Personal Access Token (PAT). The token was rejected by GitHub.', resp)
                    else:
                        # Only try to refresh the token for GitHub App authentication
                        refresh_app_token()
                        just_refreshed_token = True
                else:
                    # Reset this so that we will try to refresh the access token again later if
                    # necessary.
                    just_refreshed_token = False
                    if resp.status_code >= 500:
                        if retry_time >= MAX_RETRY_TIME:
                            raise InternalServerError('Internal server error {} persisted after '\
                                'attempting to retry for {} seconds for url {}.'.format(resp.status_code,
                                MAX_RETRY_TIME, url))
                        else:
                            logger.info('Encountered internal server error code {}, waiting {} seconds ' \
                                'and then retrying url {}.'.format(resp.status_code, RETRY_WAIT, url))
                            retry_time += RETRY_WAIT
                            time.sleep(RETRY_WAIT)
                    elif resp.status_code != 200 and resp.status_code != 201:
                        raise_for_error(resp, source, url)
                    else:
                        break
            # requests.exceptions.RequestException is the base class for all exceptions coming out of
            # the `requests` package, so we can target its errors specifically
            except requests.exceptions.RequestException as err:
                if network_retry_count <= network_max_retries:
                    network_retry_count += 1
                    logger.warning('Network request error ({}) while requesting URL (attempt {}): {}'.format(type(err).__name__, network_retry_count, url))
                    logger.info('Retrying in {} seconds'.format(network_retry_count * 30))
                    time.sleep(network_retry_count * 30) # simple linear back-off
                else:
                    logger.error('Max retries reached for network request of URL: {}'.format(url))
                    raise err

        timer.tags['response_type'] = resp.headers.get('content-type', None)
        timer.tags[metrics.Tag.http_status_code] = resp.status_code
        rate_throttling(resp)
        return resp

def authed_get_yield(source, url, headers={}):
    response = authed_get(source, url, headers)
    yield response

def authed_get_all_pages(source, url, headers={}):
    while True:
        r = authed_get(source, url, headers)
        yield r
        if 'next' in r.links:
            url = r.links['next']['url']
        else:
            break

def get_abs_path(path):
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), path)


def generate_pr_commit_schema(commit_schema):
    pr_commit_schema = commit_schema.copy()
    pr_commit_schema['properties']['pr_number'] = {
        "type":  ["null", "integer"]
    }
    pr_commit_schema['properties']['pr_id'] = {
        "type": ["null", "string"]
    }
    pr_commit_schema['properties']['id'] = {
        "type": ["null", "string"]
    }

    return pr_commit_schema

def load_schemas():
    schemas = {}

    for filename in os.listdir(get_abs_path('schemas')):
        path = get_abs_path('schemas') + '/' + filename
        file_raw = filename.replace('.json', '')
        with open(path) as file:
            schemas[file_raw] = json.load(file)
    return schemas

class DependencyException(Exception):
    pass

def validate_dependencies(selected_stream_ids):
    errs = []
    msg_tmpl = ("Unable to extract '{0}' data, "
                "to receive '{0}' data, you also need to select '{1}'.")

    for main_stream, sub_streams in SUB_STREAMS.items():
        if main_stream not in selected_stream_ids:
            for sub_stream in sub_streams:
                if sub_stream in selected_stream_ids:
                    errs.append(msg_tmpl.format(sub_stream, main_stream))

    if errs:
        raise DependencyException(" ".join(errs))


def write_metadata(mdata, values, breadcrumb):
    mdata.append(
        {
            'metadata': values,
            'breadcrumb': breadcrumb
        }
    )

def populate_metadata(schema_name, schema):
    mdata = metadata.new()
    #mdata = metadata.write(mdata, (), 'forced-replication-method', KEY_PROPERTIES[schema_name])
    mdata = metadata.write(mdata, (), 'table-key-properties', KEY_PROPERTIES[schema_name])

    for field_name in schema['properties'].keys():
        if field_name in KEY_PROPERTIES[schema_name]:
            mdata = metadata.write(mdata, ('properties', field_name), 'inclusion', 'automatic')
        else:
            mdata = metadata.write(mdata, ('properties', field_name), 'inclusion', 'available')

    return mdata

def get_catalog():
    raw_schemas = load_schemas()
    streams = []

    for schema_name, schema in raw_schemas.items():

        # get metadata for each field
        mdata = populate_metadata(schema_name, schema)

        # create and add catalog entry
        catalog_entry = {
            'stream': schema_name,
            'tap_stream_id': schema_name,
            'schema': schema,
            'metadata' : metadata.to_list(mdata),
            'key_properties': KEY_PROPERTIES[schema_name],
        }
        streams.append(catalog_entry)

    # This minimizes diffs when there are changes
    def sortFunc(val):
        return val['stream']
    streams.sort(key=sortFunc)

    return {'streams': streams}

def generate_jwt(pem, appid):
    secret = pem
    algorithm = "RS256"
    now = int(time.time())

    encoded_jwt = jwt.encode({
        # issued at time, 60 seconds in the past to allow for clock drift
        "iat": now - 60,
        # JWT expiration time (10 minute maximum, so use 8 minutes -- we will use this token
        # immediately anyway)
        "exp": now + (8 * 60),
        # GitHub App's identifier
        "iss": appid
    }, secret, algorithm)

    return encoded_jwt

# TODO: REMOVE AFTER INSTALLATION_ID ROLLOUT
def fetch_installations():
    '''
    Before this function is called, an authorization header with a JWT bearer token should be set in
    the session.
    '''
    logger.info('Fetching installations')

    # This obviously won't scale. As one step toward scaling, we may want to cache this mapping in
    # the state file and only fetch new ones. As a long-term solution, we will need to maintain a
    # table of installations and IDs with the github app web hook and then do an indexed lookup
    # to provide the installation ID as a config parameter to this script instead of looking it up
    # this way.
    account_to_installation = {}
    for response in authed_get_all_pages(
        'installations',
        '{}app/installations'.format(api_url)
    ):
        installations = response.json()
        for installation in installations:
            account_to_installation[installation['account']['login'].lower()] = installation['id']

    return account_to_installation

def get_installation_token(installation_id):
    '''
    For now, just get a new token here for now instead of caching if one already exists.
    '''
    response = authed_get(
        'installation_token',
        '{}app/installations/{}/access_tokens'.format(api_url, installation_id),
        overrideMethod='post'
    )
    token_info = response.json()
    return token_info['token']

# Cache the set of installations for the duration of this script so we don't neeed to keep hitting
# the installation list endpoint.
cached_installations = False
cached_app_tokens = {}
last_token_pem=False
last_token_appid=False
last_token_org=False
last_token_installation_id=False
def refresh_app_token(pem=None, appid=None, org=None, installation_id=None):
    global cached_installations

    # Cache the parameters so this can be called to refresh the token without any new parameters
    global last_token_pem
    global last_token_appid
    global last_token_org
    global last_token_installation_id
    if pem == None:
        pem = last_token_pem
    else:
        last_token_pem = pem
    if appid == None:
        appid = last_token_appid
    else:
        last_token_appid = appid
    if org == None:
        org = last_token_org
    else:
        last_token_org = org
    
    if installation_id == None:
        installation_id = last_token_installation_id
    else:
        last_token_installation_id = installation_id

    # Set HTTP authorization to JWT
    jwt = generate_jwt(pem, appid)
    session.headers.update({'authorization': 'Bearer ' + jwt})
    logger.info(f'USING INSTALLATION ID {installation_id}')

    # TODO: REMOVE AFTER INSTALLATION_ID ROLLOUT
    if not installation_id:
        # Get all installations if they haven't been fetched yet
        if not cached_installations:
            cached_installations = fetch_installations()

        # And make sure we have an installation for this org
        if not cached_installations.get(org.lower()):
            raise NotFoundException('No app installation found for org ' + org)

        installation_id = cached_installations[org.lower()]

    installation_token = get_installation_token(installation_id)

    # Now we have a token we can just use the same way that we use a personal access token

    # Update session auth headers to use this token
    session.headers.update({'authorization': 'token ' + installation_token})

    # cache the token to avoid possibility of requesting another one until it expires
    cached_app_tokens[org] = installation_token

    logger.addToken(installation_token)

    return installation_token

accountTypeCache = {}
def getAccountType(org):
    if not org in accountTypeCache:
        response = authed_get('account', f'{api_url}users/{org}')
        account = response.json()
        accountTypeCache[org] = account['type'].upper()

    return accountTypeCache[org]

def getReposForOrg(user_or_org):
    if getAccountType(user_or_org) == 'USER':
        repos_url = f'{api_url}search/repositories?q=user:{user_or_org}&per_page=100'
    else:
        repos_url = f'{api_url}orgs/{user_or_org}/repos?per_page=100'

    orgRepos = []
    try:
        for response in authed_get_all_pages(
            'repositories',
            repos_url,
        ):
            json_response = response.json()
            repos = json_response
            if repos_url.startswith(f'{api_url}search'):
                repos = repos.get('items', [])
     
            for repo in repos:
                # Preserve the case used for the org name originally
                namesplit = repo['full_name'].split('/')
                orgRepos.append(user_or_org + '/' + namesplit[1])
                repo_cache[repo['full_name']] = repo
    except UnprocessableError as e:
        # Log the error but don't raise an exception
        # we end up here if there are no repos for the org
        logger.warning(f"Unable to get repositories for {user_or_org}: {str(e)}")
        # Return empty list instead of raising exception
        return []

    return orgRepos

def getOrgs():
    orgs = []
    for response in authed_get_all_pages(
        'repositories',
        f'{api_url}user/orgs?per_page=100'
    ):
        orgPayloads = response.json()
        for org in orgPayloads:
            orgs.append(org['login'])

    return orgs

def set_auth_headers(config, org = None):
    global using_pat
    access_token = config['access_token']

    # If we don't have a personal access token, use the github app to get an installation access
    # token
    if not access_token or len(access_token) == 0:
        using_pat = False
        if not org and not installation_id:
            raise Exception('org or installation_id must be provided when authorizing with an app installation key')
        elif org in cached_app_tokens:
            return cached_app_tokens[org]
        pem = config['app_pem']
        appid = config['app_id']
        installation_id = config.get('installation_id', None)
        access_token = refresh_app_token(pem, appid, org, installation_id)
    else:
        using_pat = True
        session.headers.update({'authorization': 'token ' + access_token})

    logger.addToken(access_token)

    return access_token


def verify_repo_access(url_for_repo, repo):
    try:
        authed_get("verifying repository access", url_for_repo)
    except NotFoundException:
        # throwing user-friendly error message as it checks token access
        message = "HTTP-error-code: 404, Error: Please check the repository name \'{}\' or you do not have sufficient permissions to access this repository.".format(repo)
        raise NotFoundException(message) from None

def verify_access_for_repo(config):

    repositories = list(filter(None, config['repository'].split(' ')))

    for repo in repositories:
        logger.info("Verifying access of repository: %s", repo)

        url_for_repo = "{}repos/{}/commits".format(api_url, repo)

        # Verifying for Repo access
        verify_repo_access(url_for_repo, repo)

def do_discover(config):
    # We don't need repo access if we're just dumping the catalog
    #verify_access_for_repo(config)
    catalog = get_catalog()
    # dump catalog
    print(json.dumps(catalog, indent=2))

def get_all_teams(schemas, repo_path, state, mdata, _start_date):
    org = repo_path.split('/')[0]

    # Only fetch this once per org
    if process_globals == False or has_org_cache(org, 'teams'):
        return state

    # for user accounts, a GitHub app cannot access teams so we just skip the import
    if getAccountType(org) == 'USER':
        return state

    set_has_org_cache(org, 'teams')

    with metrics.record_counter('teams') as counter:
        try:
            for response in authed_get_all_pages(
                    'teams',
                    '{}orgs/{}/teams?sort=created_at&direction=desc'.format(api_url, org)
            ):
                teams = response.json()
                extraction_time = singer.utils.now()

                for r in teams:
                    team_slug = r.get('slug')
                    r['_sdc_repository'] = repo_path

                    # transform and write release record
                    with singer.Transformer(pre_hook=utf8_hook) as transformer:
                        rec = transformer.transform(r, schemas['teams'], metadata=metadata.to_map(mdata))
                    singer.write_record('teams', rec, time_extracted=extraction_time)
                    singer.write_bookmark(state, repo_path, 'teams', {'since': singer.utils.strftime(extraction_time)})
                    counter.increment()

                    if schemas.get('team_members'):
                        for team_members_rec in get_all_team_members(team_slug, schemas['team_members'], repo_path, state, mdata):
                            singer.write_record('team_members', team_members_rec, time_extracted=extraction_time)
                            singer.write_bookmark(state, repo_path, 'team_members', {'since': singer.utils.strftime(extraction_time)})

                    if schemas.get('team_memberships'):
                        for team_memberships_rec in get_all_team_memberships(team_slug, schemas['team_memberships'], repo_path, state, mdata):
                            singer.write_record('team_memberships', team_memberships_rec, time_extracted=extraction_time)
        except AuthException as err:
            # Original error:
            # {'message': 'Must have admin rights to Repository.', 'documentation_url':
            # 'https://docs.github.com/rest/reference/teams#list-teams'}
            logger.info('Received 403 unauthorized while trying to access teams. You must' \
                    ' have admin access to load teams, skipping stream for repo {}.'\
                    .format(repo_path))
        except NotFoundException as err:
            # This can happen for individual accounts, so ignore in that case
            logger.info('Received 404 not found while trying to access teams. This may be a ' \
                    'personal account without teams. Skipping stream for repo {}.'\
                    .format(repo_path))

    return state

def get_all_team_members(team_slug, schemas, repo_path, state, mdata):
    org = repo_path.split('/')[0]

    with metrics.record_counter('team_members') as counter:
        for response in authed_get_all_pages(
                'team_members',
                '{}orgs/{}/teams/{}/members?sort=created_at&direction=desc'.format(api_url, org, team_slug)
        ):
            team_members = response.json()
            for r in team_members:
                r['_sdc_repository'] = repo_path

                # transform and write release record
                with singer.Transformer(pre_hook=utf8_hook) as transformer:
                    rec = transformer.transform(r, schemas, metadata=metadata.to_map(mdata))
                counter.increment()

                yield rec

    return state

def get_all_team_memberships(team_slug, schemas, repo_path, state, mdata):
    org = repo_path.split('/')[0]

    for response in authed_get_all_pages(
            'team_members',
            '{}orgs/{}/teams/{}/members?sort=created_at&direction=desc'.format(api_url, org, team_slug)
        ):
        team_members = response.json()
        with metrics.record_counter('team_memberships') as counter:
            for r in team_members:
                username = r['login']
                for res in authed_get_all_pages(
                        'memberships',
                        '{}orgs/{}/teams/{}/memberships/{}'.format(api_url, org, team_slug, username)
                ):
                    team_membership = res.json()
                    team_membership['_sdc_repository'] = repo_path
                    with singer.Transformer(pre_hook=utf8_hook) as transformer:
                        rec = transformer.transform(team_membership, schemas, metadata=metadata.to_map(mdata))
                    counter.increment()
                    yield rec
    return state


def get_all_issue_events(schemas, repo_path, state, mdata, start_date):
    bookmark_value = get_bookmark(state, repo_path, "issue_events", "since", start_date)
    if bookmark_value:
        bookmark_time = singer.utils.strptime_to_utc(bookmark_value)
    else:
        bookmark_time = 0


    with metrics.record_counter('issue_events') as counter:
        for response in authed_get_all_pages(
                'issue_events',
                '{}repos/{}/issues/events?per_page=100&sort=created_at&direction=desc'.format(api_url, repo_path),
                { 'Accept': 'application/vnd.github.starfox-preview+json' }
        ):
            events = response.json()
            extraction_time = singer.utils.now()
            for event in events:
                event['_sdc_repository'] = repo_path
                # skip records that haven't been updated since the last run
                # the GitHub API doesn't currently allow a ?since param for pulls
                # once we find the first piece of old data we can return, thanks to
                # the sorting
                updated_at = event.get('created_at') if event.get('updated_at') is None else event.get('updated_at')
                if bookmark_time and singer.utils.strptime_to_utc(updated_at) < bookmark_time:
                    return state

                # transform and write release record
                with singer.Transformer(pre_hook=utf8_hook) as transformer:
                    rec = transformer.transform(event, schemas, metadata=metadata.to_map(mdata))
                singer.write_record('issue_events', rec, time_extracted=extraction_time)
                singer.write_bookmark(state, repo_path, 'issue_events', {'since': singer.utils.strftime(extraction_time)})
                counter.increment()

    return state


def get_all_events(schemas, repo_path, state, mdata, start_date):
    # Incremental sync off `created_at`
    # https://developer.github.com/v3/issues/events/#list-events-for-a-repository
    # '{}repos/{}/issues/events?sort=created_at&direction=desc'.format(api_url, repo_path)

    CURRENT_EVENTS_VERSION = '1.0'
    bookmark_value = get_bookmark(state, repo_path, "events", "since", start_date)
    bookmark_version = get_bookmark(state, repo_path, "events", "version")
    if bookmark_value and bookmark_version == CURRENT_EVENTS_VERSION:
        bookmark_time = singer.utils.strptime_to_utc(bookmark_value)
    else:
        bookmark_time = 0

    with metrics.record_counter('events') as counter:
        for response in authed_get_all_pages(
                'events',
                '{}repos/{}/events?per_page=100&sort=created_at&direction=desc'.format(api_url, repo_path)
        ):
            events = response.json()
            extraction_time = singer.utils.now()
            for r in events:
                r['_sdc_repository'] = repo_path

                # skip records that haven't been updated since the last run
                # the GitHub API doesn't currently allow a ?since param for pulls
                # once we find the first piece of old data we can return, thanks to
                # the sorting
                updated_at = r.get('created_at') if r.get('updated_at') is None else r.get('updated_at')
                if bookmark_time and singer.utils.strptime_to_utc(updated_at) < bookmark_time:
                    return state

                # transform and write release record
                with singer.Transformer(pre_hook=utf8_hook) as transformer:
                    rec = transformer.transform(r, schemas, metadata=metadata.to_map(mdata))
                singer.write_record('events', rec, time_extracted=extraction_time)
                singer.write_bookmark(state, repo_path, 'events', {
                    'since': singer.utils.strftime(extraction_time),
                    'version': CURRENT_EVENTS_VERSION,
                })
                counter.increment()

    return state

def get_all_issue_milestones(schemas, repo_path, state, mdata, start_date):
    # Incremental sync off `due on` ??? confirm.
    # https://developer.github.com/v3/issues/milestones/#list-milestones-for-a-repository
    # '{}repos/{}/milestones?sort=created_at&direction=desc'.format(api_url, repo_path)
    bookmark_value = get_bookmark(state, repo_path, "issue_milestones", "since", start_date)
    if bookmark_value:
        bookmark_time = singer.utils.strptime_to_utc(bookmark_value)
    else:
        bookmark_time = 0

    with metrics.record_counter('issue_milestones') as counter:
        for response in authed_get_all_pages(
                'milestones',
                '{}repos/{}/milestones?state=all&per_page=100&direction=desc'.format(api_url, repo_path)
        ):
            milestones = response.json()
            extraction_time = singer.utils.now()
            for r in milestones:
                r['_sdc_repository'] = repo_path

                # skip records that haven't been updated since the last run
                # the GitHub API doesn't currently allow a ?since param for pulls
                # once we find the first piece of old data we can return, thanks to
                # the sorting
                if bookmark_time and r.get("due_on") and singer.utils.strptime_to_utc(r.get("due_on")) < bookmark_time:
                    continue

                # transform and write release record
                with singer.Transformer(pre_hook=utf8_hook) as transformer:
                    rec = transformer.transform(r, schemas, metadata=metadata.to_map(mdata))
                singer.write_record('issue_milestones', rec, time_extracted=extraction_time)
                singer.write_bookmark(state, repo_path, 'issue_milestones', {'since': singer.utils.strftime(extraction_time)})
                counter.increment()

    return state

def get_all_issue_labels(schemas, repo_path, state, mdata, _start_date):
    # https://developer.github.com/v3/issues/labels/
    # not sure if incremental key
    # '{}repos/{}/labels?sort=created_at&direction=desc'.format(api_url, repo_path)

    with metrics.record_counter('issue_labels') as counter:
        for response in authed_get_all_pages(
                'issue_labels',
                '{}repos/{}/labels?per_page=100'.format(api_url, repo_path)
        ):
            issue_labels = response.json()
            extraction_time = singer.utils.now()
            for r in issue_labels:
                r['_sdc_repository'] = repo_path

                # transform and write release record
                with singer.Transformer(pre_hook=utf8_hook) as transformer:
                    rec = transformer.transform(r, schemas, metadata=metadata.to_map(mdata))
                singer.write_record('issue_labels', rec, time_extracted=extraction_time)
                singer.write_bookmark(state, repo_path, 'issue_labels', {'since': singer.utils.strftime(extraction_time)})
                counter.increment()

    return state

def get_all_commit_comments(schemas, repo_path, state, mdata, start_date):
    # https://developer.github.com/v3/repos/comments/
    # updated_at? incremental
    # '{}repos/{}/comments?sort=created_at&direction=desc'.format(api_url, repo_path)
    bookmark_value = get_bookmark(state, repo_path, "commit_comments", "since", start_date)
    if bookmark_value:
        bookmark_time = singer.utils.strptime_to_utc(bookmark_value)
    else:
        bookmark_time = 0

    with metrics.record_counter('commit_comments') as counter:
        for response in authed_get_all_pages(
                'commit_comments',
                '{}repos/{}/comments?per_page=100&sort=created_at&direction=desc'.format(api_url, repo_path)
        ):
            commit_comments = response.json()
            extraction_time = singer.utils.now()
            for r in commit_comments:
                r['_sdc_repository'] = repo_path

                # skip records that haven't been updated since the last run
                # the GitHub API doesn't currently allow a ?since param for pulls
                # once we find the first piece of old data we can return, thanks to
                # the sorting
                if bookmark_time and singer.utils.strptime_to_utc(r.get('updated_at')) < bookmark_time:
                    return state

                # transform and write release record
                with singer.Transformer(pre_hook=utf8_hook) as transformer:
                    rec = transformer.transform(r, schemas, metadata=metadata.to_map(mdata))
                singer.write_record('commit_comments', rec, time_extracted=extraction_time)
                singer.write_bookmark(state, repo_path, 'commit_comments', {'since': singer.utils.strftime(extraction_time)})
                counter.increment()

    return state

def get_all_projects(schemas, repo_path, state, mdata, start_date):
    repoSplit = repo_path.split('/')
    org = repoSplit[0]

    # for user accounts, a GitHub app cannot access projects so we just skip the import
    if getAccountType(org) == 'USER':
        return state

    # So there are both repo projects and org projects (not tied to a repo). Every time this is
    # called, also attempt to fetch org projects, but only do that once.
    orgLevel = False
    if len(repoSplit) == 1:
        orgLevel = True
        # Load global projects -- only fetch this once per org
        if process_globals == False or has_org_cache(org, 'projects'):
            return state
    else:
        state = get_all_projects(schemas, org, state, mdata, start_date)

    bookmark_value = get_bookmark(state, repo_path, "projects", "since", start_date)
    if bookmark_value:
        bookmark_time = singer.utils.strptime_to_utc(bookmark_value)
    else:
        bookmark_time = 0

    with metrics.record_counter('projects') as counter:
        #pylint: disable=too-many-nested-blocks
        try:
            if orgLevel:
                projectUri = '{}orgs/{}/projects?per_page=100&sort=created_at&direction=desc'.format(api_url, repo_path)
            else:
                projectUri = '{}repos/{}/projects?per_page=100&sort=created_at&direction=desc'.format(api_url, repo_path)

            for response in authed_get_all_pages(
                    'projects',
                    projectUri,
                    { 'Accept': 'application/vnd.github.inertia-preview+json' }
            ):
                projects = response.json()
                extraction_time = singer.utils.now()
                for r in projects:
                    r['_sdc_repository'] = repo_path

                    # skip records that haven't been updated since the last run
                    # the GitHub API doesn't currently allow a ?since param for pulls
                    # once we find the first piece of old data we can return, thanks to
                    # the sorting
                    if bookmark_time and singer.utils.strptime_to_utc(r.get('updated_at')) < bookmark_time:
                        return state

                    # transform and write release record
                    with singer.Transformer(pre_hook=utf8_hook) as transformer:
                        rec = transformer.transform(r, schemas, metadata=metadata.to_map(mdata))
                    singer.write_record('projects', rec, time_extracted=extraction_time)
                    singer.write_bookmark(state, repo_path, 'projects', {'since': singer.utils.strftime(extraction_time)})
                    counter.increment()

                    project_id = r.get('id')

                    # sync project_columns if that schema is present (only there if selected)
                    if schemas.get('project_columns'):
                        for project_column_rec in get_all_project_columns(project_id, schemas['project_columns'], repo_path, state, mdata, start_date):
                            singer.write_record('project_columns', project_column_rec, time_extracted=extraction_time)
                            singer.write_bookmark(state, repo_path, 'project_columns', {'since': singer.utils.strftime(extraction_time)})

                            # sync project_cards if that schema is present (only there if selected)
                            if schemas.get('project_cards'):
                                column_id = project_column_rec['id']
                                for project_card_rec in get_all_project_cards(column_id, schemas['project_cards'], repo_path, state, mdata, start_date):
                                    singer.write_record('project_cards', project_card_rec, time_extracted=extraction_time)
                                    singer.write_bookmark(state, repo_path, 'project_cards', {'since': singer.utils.strftime(extraction_time)})
        except GoneError:
            logger.info('Received 410 Gone when attempting to access projects (they may be disabled for this repo), skipping import')
        except NotFoundException:
            logger.info('Received 404 Not Found when attempting to access projects (the access token may not have access to projects), skipping import')
    return state

def get_all_project_cards(column_id, schemas, repo_path, state, mdata, start_date):
    bookmark_value = get_bookmark(state, repo_path, "project_cards", "since", start_date)
    if bookmark_value:
        bookmark_time = singer.utils.strptime_to_utc(bookmark_value)
    else:
        bookmark_time = 0

    with metrics.record_counter('project_cards') as counter:
        for response in authed_get_all_pages(
                'project_cards',
                '{}projects/columns/{}/cards?per_page=100&sort=created_at&direction=desc'.format(api_url, column_id)
        ):
            project_cards = response.json()
            for r in project_cards:
                r['_sdc_repository'] = repo_path

                # skip records that haven't been updated since the last run
                # the GitHub API doesn't currently allow a ?since param for pulls
                # once we find the first piece of old data we can return, thanks to
                # the sorting
                if bookmark_time and singer.utils.strptime_to_utc(r.get('updated_at')) < bookmark_time:
                    return state

                # transform and write release record
                with singer.Transformer(pre_hook=utf8_hook) as transformer:
                    rec = transformer.transform(r, schemas, metadata=metadata.to_map(mdata))
                counter.increment()
                yield rec

    return state

def get_all_project_columns(project_id, schemas, repo_path, state, mdata, start_date):
    bookmark_value = get_bookmark(state, repo_path, "project_columns", "since", start_date)
    if bookmark_value:
        bookmark_time = singer.utils.strptime_to_utc(bookmark_value)
    else:
        bookmark_time = 0

    with metrics.record_counter('project_columns') as counter:
        for response in authed_get_all_pages(
                'project_columns',
                '{}projects/{}/columns?per_page=100&sort=created_at&direction=desc'.format(api_url, project_id)
        ):
            project_columns = response.json()
            for r in project_columns:
                r['_sdc_repository'] = repo_path

                # skip records that haven't been updated since the last run
                # the GitHub API doesn't currently allow a ?since param for pulls
                # once we find the first piece of old data we can return, thanks to
                # the sorting
                if bookmark_time and singer.utils.strptime_to_utc(r.get('updated_at')) < bookmark_time:
                    return state

                # transform and write release record
                with singer.Transformer(pre_hook=utf8_hook) as transformer:
                    rec = transformer.transform(r, schemas, metadata=metadata.to_map(mdata))
                counter.increment()
                yield rec

    return state

# IMPORTANT: The `query_template` must contain two variables in it named
# {page_size} and {cursor} that the function will replace with values as
# it loops. It also must select the `totalCount` and `pageInfo { endCursor }`
# properties within the object being paged.
#
# See `get_all_projects_v2` for example usage.
def authed_graphql_all_pages(source, query_template, query_values, path, page_size = 100, max_pages = 500):
    global graphql_url

    totalRetrievedCount = 0
    query_values = {
        **query_values,
        'page_size': page_size,
        'cursor': '',
    }

    for i in range(max_pages):
        # generate the query by filling in the template using values from the caller that have
        # been combined with our own paging values (page_size, cursor)
        query = query_template.format(**query_values)

        # make GraphQL query
        post_body = json.dumps({ 'query': query })
        data = authed_get(source, f'{graphql_url}', {}, 'post', post_body)
        data = data.json()

        errors = data.get('errors')
        # check for errors
        if errors is not None:
            logger.info('GraphQL call failed with query: %s', query)            
            if any(err.get('type') in ['FORBIDDEN', 'INSUFFICIENT_SCOPES'] for err in errors):
                raise AuthException(errors[0]['message'], data)
            logger.error('GraphQL query failed on page {}: {}'.format(i + 1, errors))
            raise Exception('GraphQL query failed', errors)

        # extract the data by drilling down into the returned object based on
        # the input path array (e.g. ['organization', 'projectsV2'])
        data = data['data']
        for name in path:
            data = data[name]

        yield data['nodes']

        query_values['cursor'] = data['pageInfo']['endCursor']
        totalRetrievedCount += len(data['nodes'])
        totalAvailableCount = data['totalCount']

        # if there is no cursor left to query against or we have retrieved all of
        # the available objects based on count, then break the loop
        if query_values['cursor'] is None or totalRetrievedCount >= totalAvailableCount:
            break

projects_v2 = []

def get_all_projects_v2(schemas, repo_path, state, mdata, _start_date):
    stream_name = 'projects_v2'
    org = repo_path.split('/')[0]
    acctObjectName = 'user' if getAccountType(org) == 'USER' else 'organization'

    # Only fetch this once per org
    if process_globals == False or has_org_cache(org, stream_name):
        return state

    set_has_org_cache(org, stream_name, True)

    extraction_time = singer.utils.now()

    with metrics.record_counter(stream_name) as counter:
        path = [acctObjectName, 'projectsV2']
        query_template = '''query {{
            {acctObjectName}(login:"{org}") {{
                projectsV2(first: 10, after: "{cursor}") {{
                    totalCount
                    pageInfo {{
                        endCursor
                    }}
                    nodes {{
                        title
                        closed
                        closedAt
                        createdAt
                        creator {{
                            avatarUrl
                            login
                            resourcePath
                            url
                        }}
                        databaseId
                        id
                        number
                        public
                        resourcePath
                        shortDescription
                        title
                        url
                    }}
                }}
            }}
        }}'''
        query_values = {
            'org': org,
            'acctObjectName': acctObjectName,
        }

        try:
            for projects in authed_graphql_all_pages(stream_name, query_template, query_values, path):
                # store in cache for later usage in child streams
                projects_v2.extend(projects)

                for project in projects:
                    # Can happen with access tokens that can't access projects
                    if not project:
                        continue
                    project['_sdc_org'] = org
                    # transform and write record
                    with singer.Transformer(pre_hook=utf8_hook) as transformer:
                        rec = transformer.transform(project, schemas, metadata=metadata.to_map(mdata))
                    singer.write_record(stream_name, rec, time_extracted=extraction_time)
                    counter.increment()
        except AuthException as err:
            logger.warn('Projects v2 data could not be ingested because authorization failed')

    return state


def get_all_projects_v2_issues(schemas, repo_path, state, mdata, _start_date):
    stream_name = 'projects_v2_issues'
    org = repo_path.split('/')[0]
    acctObjectName = 'user' if getAccountType(org) == 'USER' else 'organization'

    # Only fetch this once per org
    if process_globals == False or has_org_cache(org, stream_name):
        return state

    set_has_org_cache(org, stream_name, True)

    extraction_time = singer.utils.now()

    with metrics.record_counter(stream_name) as counter:
        path = [acctObjectName, 'projectV2', 'items']
        query_template = '''query {{
            {acctObjectName}(login:"{org}") {{
                projectV2(number: {project_number}) {{
                    items(first: {page_size}, after: "{cursor}") {{
                        totalCount
                        pageInfo {{
                            endCursor
                        }}
                        nodes {{
                            type
                            createdAt
                            updatedAt
                            content {{
                                ... on Issue {{
                                    id
                                    databaseId
                                    number
                                }}
                            }}
                            fieldValues(first: 50) {{
                                nodes {{
                                    ... on ProjectV2ItemFieldValueCommon {{
                                        id
                                        databaseId
                                        createdAt
                                        updatedAt
                                        field {{
                                            ... on ProjectV2FieldCommon {{
                                                id
                                                databaseId
                                                createdAt
                                                updatedAt
                                                dataType
                                                name
                                                typename: __typename
                                            }}
                                        }}
                                    }}
                                    ... on ProjectV2ItemFieldDateValue {{
                                        date
                                    }}
                                    ... on ProjectV2ItemFieldIterationValue {{
                                        duration
                                        iterationId
                                        startDate
                                        title
                                    }}
                                    ... on ProjectV2ItemFieldNumberValue {{
                                        number
                                    }}
                                    ... on ProjectV2ItemFieldSingleSelectValue {{
                                        name
                                        optionId
                                    }}
                                    ... on ProjectV2ItemFieldTextValue {{
                                        text
                                    }}
                                }}
                            }}
                        }}
                    }}
                }}
            }}
        }}'''

        # for each project we cached during get_all_projects_v2, page through its
        # associated issues
        for project in projects_v2:
            # Can happen with access tokens that can't access projects
            if not project:
                continue
            query_values = {
                'org': org,
                'project_number': project['number'],
                'acctObjectName': acctObjectName,
            }

            for issues in authed_graphql_all_pages(stream_name, query_template, query_values, path):
                for issue in issues:
                    # various kinds of "items" come back in the query, but we are only interested
                    # to ingest issues for this stream
                    if issue['type'] != 'ISSUE':
                        continue

                    issue['projectV2'] = project

                    # squash the issue content object back into the root issue object
                    issue.update(issue['content'])

                    # filter out field values which are empty. this will happen for v1 fields that we are
                    # not interested to absorb in this v2 stream
                    issue['fieldValues'] = list(filter(lambda value: len(value) > 0, issue['fieldValues']['nodes']))

                    # transform and write record
                    with singer.Transformer(pre_hook=utf8_hook) as transformer:
                        rec = transformer.transform(issue, schemas, metadata=metadata.to_map(mdata))
                    singer.write_record(stream_name, rec, time_extracted=extraction_time)
                    counter.increment()

    return state

def get_all_code_coverage(schemas, repo_path, state, mdata, start_date):
    stream_name = 'code_coverage'
    repo_name = repo_path.split('/')[1]

    bookmark_value = get_bookmark(state, repo_path, stream_name, "since", start_date)
    if bookmark_value:
        bookmark_time = singer.utils.strptime_to_utc(bookmark_value)
    else:
        bookmark_time = 0

    extraction_time = singer.utils.now()

    with metrics.record_counter(stream_name) as counter:
        artifact_name_encoded = urllib.parse.quote(code_coverage_artifact_name)

        try:
            for response in authed_get_all_pages(
                    stream_name,
                    '{}repos/{}/actions/artifacts?name={}'.format(api_url, repo_path, artifact_name_encoded)
            ):
                artifacts = filter(lambda a: a['expired'] != True, response.json()['artifacts'])
                for artifact in artifacts:
                    # skip records that haven't been updated since the last run.
                    # the GitHub API doesn't currently allow a `?since` param for artifacts, so we have
                    # to iterate them all, but we only need to process the ones that are new since our
                    # last bookmark.
                    if bookmark_time and singer.utils.strptime_to_utc(artifact.get('updated_at')) < bookmark_time:
                        continue

                    # the endpoint actually returns a 302 redirect, but authed_get is coded in such a way that
                    # the redirect is followed automatically, thus we get the actual artifact binary data response
                    # here. also, take note that it is always a zip file, even if the original artifact was
                    # a single file.
                    # ref: https://docs.github.com/en/rest/actions/artifacts?apiVersion=2022-11-28
                    data = authed_get(stream_name, artifact['archive_download_url'])

                    # load zip file into memory
                    zip = zipfile.ZipFile(io.BytesIO(data.content))

                    # if the expected clover.xml file is not in the zip file, skip it
                    if 'clover.xml' not in zip.namelist():
                        continue

                    # load clover.xml file into memory
                    file = zip.open('clover.xml')
                    xml = file.read()

                    # parse the clover.xml data into a tree
                    root = ET.fromstring(xml)

                    # collect all package stats and emit each record
                    for package in root.iter('package'):
                        for package_file in package.iter('file'):
                            file_metrics = next(package_file.iterfind('metrics'))

                            full_path = package_file.get('path')
                            if full_path.startswith('/home/runner'):
                                # when executed from within GitHub Actions the file path is absolute and
                                # thus includes the Github worker root folder (e.g. /home/runner/...). splitting
                                # on the repo name with maximum splits = 1 allows us to get the file path relative
                                # to the repo root.
                                relative_path = full_path.split(repo_name, 1)[1][len(repo_name) + 2:]
                            elif full_path.startswith('/app'):
                                relative_path = full_path[5:]
                            else:
                                # fall back to full path
                                relative_path = full_path

                            coverage = {
                                '_sdc_repository': repo_path,
                                'id': '{}/{}'.format(repo_path, relative_path),
                                'branch_name': artifact['workflow_run']['head_branch'],
                                'commit_sha': artifact['workflow_run']['head_sha'],
                                'file_path': relative_path,
                                'file_name': package_file.get('name'),
                                'statements': int(file_metrics.get('statements')),
                                'covered_statements': int(file_metrics.get('coveredstatements')),
                                'functions': int(file_metrics.get('methods')),
                                'covered_functions': int(file_metrics.get('coveredmethods')),
                                'branches': int(file_metrics.get('conditionals')),
                                'covered_branches': int(file_metrics.get('coveredconditionals')),
                                'created_at': artifact['created_at'],
                                'updated_at': artifact['updated_at'],
                            }

                            # transform and write the record
                            with singer.Transformer(pre_hook=utf8_hook) as transformer:
                                rec = transformer.transform(coverage, schemas, metadata=metadata.to_map(mdata))
                            singer.write_record(stream_name, rec, time_extracted=extraction_time)
                            counter.increment()

                        singer.write_bookmark(state, repo_path, stream_name, {'since': artifact['updated_at']})
        except AuthException as err:
            logger.warn('Code coverage data could not be ingested because authorization failed on the GitHub Actions artifacts endpoint')
            # do not throw for this yet because most orgs do not have this permission yet


    return state

def get_all_workflows(schemas, repo_path, state, mdata, start_date):
    stream_name = 'workflows'

    extraction_time = singer.utils.now()

    with metrics.record_counter(stream_name) as counter:
        try:
            for response in authed_get_all_pages(
                    stream_name,
                    '{}repos/{}/actions/workflows'.format(api_url, repo_path)
            ):
                workflows = response.json()['workflows']

                for workflow in workflows:
                    workflow_record = {
                        **workflow,
                        '_sdc_repository': repo_path
                    }
                    # transform and write the record
                    with singer.Transformer(pre_hook=utf8_hook) as transformer:
                        rec = transformer.transform(
                            workflow_record,
                            schemas,
                            metadata=metadata.to_map(mdata)
                        )
                    singer.write_record(stream_name, rec, time_extracted=extraction_time)
                    counter.increment()
        except AuthException:
            logger.warn('{} data could not be ingested because authorization failed on the API endpoint'
                    .format(stream_name, repo_path))

    return state

def get_all_workflow_runs(schemas, repo_path, state, mdata, start_date):
    stream_name = 'workflow_runs'

    bookmark_value = get_bookmark(state, repo_path, stream_name, "since", start_date)

    if isinstance(bookmark_value, str):
        bookmark_time = singer.utils.strptime_to_utc(bookmark_value)

    extraction_time = singer.utils.now()

    with metrics.record_counter(stream_name) as counter:
        try:
            url = '{}repos/{}/actions/runs?per_page=100'.format(api_url, repo_path)
            for response in authed_get_all_pages(stream_name,url):
                response_json = response.json()
                workflow_runs = response_json['workflow_runs']

                for workflow_run in workflow_runs:
                    workflow_run_record = {
                        **workflow_run,
                        '_sdc_repository': repo_path
                    }

                    updated_at_date = singer.utils.strptime_to_utc(workflow_run['updated_at'])
                    if updated_at_date < bookmark_time:
                        continue

                    # transform and write the record
                    with singer.Transformer(pre_hook=utf8_hook) as transformer:
                        rec = transformer.transform(
                            workflow_run_record,
                            schemas,
                            metadata=metadata.to_map(mdata)
                        )
                    singer.write_record(stream_name, rec, time_extracted=extraction_time)
                    counter.increment()

                    if schemas.get('workflow_run_jobs'):
                        state = get_all_workflow_run_jobs(
                            schemas,
                            repo_path,
                            workflow_run['id'],
                            workflow_run['run_attempt'],
                            state,
                            mdata,
                            start_date
                        )
        except AuthException:
            logger.warn('{} data could not be ingested because authorization failed on the API endpoint'
                    .format(stream_name, repo_path))
    # set the bookmark to the earliest incomplete workflow run or the latest created workflow run
    singer.write_bookmark(state, repo_path, stream_name, {'since': singer.utils.strftime(extraction_time)})

    return state

def get_all_workflow_run_jobs(schemas, repo_path, run_id, attempt, state, mdata, start_date):
    stream_name = 'workflow_run_jobs'

    extraction_time = singer.utils.now()

    with metrics.record_counter(stream_name) as counter:
        for response in authed_get_all_pages(
            stream_name,
            '{}repos/{}/actions/runs/{}/attempts/{}/jobs?per_page=100'.format(api_url, repo_path, run_id, attempt)
        ):
            workflow_run_jobs = response.json()['jobs']

            for workflow_run_job in workflow_run_jobs:
                workflow_run_job_record = {
                    **workflow_run_job,
                    '_sdc_repository': repo_path
                }
                # transform and write the record
                with singer.Transformer(pre_hook=utf8_hook) as transformer:
                    rec = transformer.transform(
                        workflow_run_job_record,
                        schemas,
                        metadata=metadata.to_map(mdata)
                    )
                singer.write_record(stream_name, rec, time_extracted=extraction_time)
                counter.increment()

    return state

def get_all_deployments(schemas, repo_path, state, mdata, start_date):
    stream_name = 'deployments'
    org = repo_path.split('/')[0]
    name = repo_path.split('/')[1]

    bookmark_value = get_bookmark(state, repo_path, stream_name, "since", start_date)

    if isinstance(bookmark_value, str):
        bookmark_time = singer.utils.strptime_to_utc(bookmark_value)

    extraction_time = singer.utils.now()

    with metrics.record_counter(stream_name) as counter:
        path = ['repository', 'deployments']
        query_template = '''query {{
            repository(owner: "{org}", name:"{name}") {{
                deployments(first: {page_size}, after: "{cursor}", orderBy:{{field: CREATED_AT, direction: DESC}}) {{
                    pageInfo {{
                        endCursor
                    }}
                    totalCount
                    nodes {{
                        id
                        task
                        payload
                        originalEnvironment
                        environment
                        description
                        state
                        latestEnvironment
                        ref {{
                            id
                            name
                            prefix
                            target {{
                                id
                                commitUrl
                                commitResourcePath
                                repository {{
                                    nameWithOwner
                                    url
                                }}
                            }}
                        }}
                        creator {{
                            resourcePath
                            login
                            url
                            avatarUrl
                            resourcePath
                        }}
                        createdAt
                        updatedAt
                        repository {{
                            nameWithOwner
                            url
                        }}
                        latestStatus {{
                            createdAt
                            description
                            environment
                            environmentUrl
                            id
                            logUrl
                            updatedAt
                        }}
                    }}
                }}
            }}
        }}'''
        query_values = {
            'org': org,
            'name': name,
        }

        try:
            for deployments in authed_graphql_all_pages(stream_name, query_template, query_values, path):
                for deployment in deployments:
                    deployment_record = {
                        **camel_to_snake_dict(deployment),
                        '_sdc_repository': repo_path
                    }

                    updated_at_date = singer.utils.strptime_to_utc(deployment['updatedAt'])
                    if updated_at_date < bookmark_time:
                        continue

                    # transform and write record
                    with singer.Transformer(pre_hook=utf8_hook) as transformer:
                        rec = transformer.transform(deployment_record, schemas, metadata=metadata.to_map(mdata))
                        singer.write_record(stream_name, rec, time_extracted=extraction_time)

                    counter.increment()

                    if schemas.get('deployment_statuses'):
                        get_all_deployment_statuses(
                            schemas,
                            repo_path,
                            deployment['id'],
                            state,
                            mdata,
                            start_date
                        )

            singer.write_bookmark(state, repo_path, stream_name, {'since': singer.utils.strftime(extraction_time)})

        # if we do NOT have permissions to access deployments
        # do NOT fail tap, just return
        except AuthException:
            logger.warn('Skipping {} because resource is not accessible'.format(stream_name))

    return state

def get_all_deployment_statuses(schemas, repo_path, deployment_id, _state, mdata, _start_date):
    stream_name = 'deployment_statuses'
    org = repo_path.split('/')[0]
    name = repo_path.split('/')[1]

    extraction_time = singer.utils.now()

    with metrics.record_counter(stream_name) as counter:
        path = ['node', 'statuses']
        query_template = '''query {{
            node(id: "{id}") {{
                id
                ... on Deployment {{
                    statuses(first: {page_size}, after: "{cursor}") {{
                        pageInfo {{
                            endCursor
                        }}
                        totalCount
                        nodes {{
                            creator {{
                                url
                                login
                                avatarUrl
                                resourcePath
                            }}
                            id
                            description
                            environment
                            environmentUrl
                            logUrl
                            createdAt
                            updatedAt
                            state
                        }}
                    }}
                }}
            }}
        }}'''
        query_values = {
            'id': deployment_id,
            'org': org,
            'name': name,
        }

        for deployments_statuses in authed_graphql_all_pages(stream_name, query_template, query_values, path):
            for deployments_status in deployments_statuses:
                deployment_record = {
                    **camel_to_snake_dict(deployments_status),
                    'deployment_id': deployment_id,
                    '_sdc_repository': repo_path
                }

                # transform and write record
                with singer.Transformer(pre_hook=utf8_hook) as transformer:
                    rec = transformer.transform(deployment_record, schemas, metadata=metadata.to_map(mdata))
                    singer.write_record(stream_name, rec, time_extracted=extraction_time)

                counter.increment()

def get_all_releases(schemas, repo_path, state, mdata, _start_date):
    # Releases doesn't seem to have an `updated_at` property, yet can be edited.
    # For this reason and since the volume of release can safely be considered low,
    #    bookmarks were ignored for releases.

    with metrics.record_counter('releases') as counter:
        for response in authed_get_all_pages(
                'releases',
                '{}repos/{}/releases?per_page=100&sort=created_at&direction=desc'.format(api_url, repo_path)
        ):
            releases = response.json()
            extraction_time = singer.utils.now()
            for r in releases:
                r['_sdc_repository'] = repo_path

                # transform and write release record
                with singer.Transformer(pre_hook=utf8_hook) as transformer:
                    rec = transformer.transform(r, schemas, metadata=metadata.to_map(mdata))
                singer.write_record('releases', rec, time_extracted=extraction_time)
                singer.write_bookmark(state, repo_path, 'releases', {'since': singer.utils.strftime(extraction_time)})
                counter.increment()

    return state

PR_CACHE = {}
def get_all_pull_requests(schemas, repo_path, state, mdata, start_date):
    '''
    https://developer.github.com/v3/pulls/#list-pull-requests
    '''
    cur_cache = {}
    PR_CACHE[repo_path] = cur_cache

    bookmark_value = get_bookmark(state, repo_path, "pull_requests", "since", start_date)
    if bookmark_value:
        bookmark_time = singer.utils.strptime_to_utc(bookmark_value)
    else:
        bookmark_time = 0

    with metrics.record_counter('pull_requests') as counter:
        with metrics.record_counter('reviews') as reviews_counter:
            for response in authed_get_all_pages(
                    'pull_requests',
                    '{}repos/{}/pulls?per_page=100&state=all&sort=updated&direction=desc'.format(api_url, repo_path)
            ):
                pull_requests = response.json()
                extraction_time = singer.utils.now()
                for pr in pull_requests:
                    # Skip records that haven't been updated since the last run because
                    # the GitHub API doesn't currently allow a ?since param for pulls.
                    # Return early in this case to stop querying pages of pull requests.
                    # PRs get "updated" when the head or base changes, so those commits will have
                    # been fetched in a previous run.
                    if bookmark_time and singer.utils.strptime_to_utc(pr.get('updated_at')) < bookmark_time:
                        return state

                    pr_num = pr.get('number')
                    pr_id = pr.get('id')
                    pr['_sdc_repository'] = repo_path

                    # Cache the commit into for commit fetching
                    cur_cache[str(pr_num)] = {
                        'pr_num': str(pr_num),
                        'base_sha': pr['base']['sha'],
                        'base_ref': pr['base']['ref'],
                        'head_sha': pr['head']['sha'],
                        'head_ref': pr['head']['ref']
                    }

                    # transform and write pull_request record
                    with singer.Transformer(pre_hook=utf8_hook) as transformer:
                        rec = transformer.transform(pr, schemas['pull_requests'], metadata=metadata.to_map(mdata))
                    singer.write_record('pull_requests', rec, time_extracted=extraction_time)
                    # BUGBUG? What if there's a failure to load the reviews, review comments, or pr
                    # commits for this PR? Wouldn't they then not be fetched later?
                    singer.write_bookmark(state, repo_path, 'pull_requests', {'since': singer.utils.strftime(extraction_time)})
                    counter.increment()

                    # sync reviews if that schema is present (only there if selected)
                    if schemas.get('reviews'):
                        for review_rec in get_reviews_for_pr(pr_num, schemas['reviews'], repo_path, state, mdata):
                            singer.write_record('reviews', review_rec, time_extracted=extraction_time)
                            singer.write_bookmark(state, repo_path, 'reviews', {'since': singer.utils.strftime(extraction_time)})

                            reviews_counter.increment()

                    # sync review comments if that schema is present (only there if selected)
                    if schemas.get('review_comments'):
                        for review_comment_rec in get_review_comments_for_pr(pr_num, schemas['review_comments'], repo_path, state, mdata):
                            singer.write_record('review_comments', review_comment_rec, time_extracted=extraction_time)
                            singer.write_bookmark(state, repo_path, 'review_comments', {'since': singer.utils.strftime(extraction_time)})

                    # We eliminated pr_commits entirely since they can now be obtained by following
                    # the head commit from a PR.

    return state

def get_reviews_for_pr(pr_number, schema, repo_path, state, mdata):
    for response in authed_get_all_pages(
            'reviews',
            '{}repos/{}/pulls/{}/reviews?per_page=100'.format(api_url, repo_path,pr_number)
    ):
        reviews = response.json()
        for review in reviews:
            review['_sdc_repository'] = repo_path
            with singer.Transformer(pre_hook=utf8_hook) as transformer:
                rec = transformer.transform(review, schema, metadata=metadata.to_map(mdata))
            yield rec


        return state

def get_review_comments_for_pr(pr_number, schema, repo_path, state, mdata):
    for response in authed_get_all_pages(
            'comments',
            '{}repos/{}/pulls/{}/comments?per_page=100'.format(api_url, repo_path,pr_number)
    ):
        review_comments = response.json()
        for comment in review_comments:
            comment['_sdc_repository'] = repo_path
            with singer.Transformer(pre_hook=utf8_hook) as transformer:
                rec = transformer.transform(comment, schema, metadata=metadata.to_map(mdata))
            yield rec


        return state

def get_all_assignees(schema, repo_path, state, mdata, _start_date):
    '''
    https://developer.github.com/v3/issues/assignees/#list-assignees

    No "since" parameter available, so have to get all of them each time, which can be a lot
    (thousands) for very large repositories with a lot of contributors.
    '''
    with metrics.record_counter('assignees') as counter:
        for response in authed_get_all_pages(
                'assignees',
                '{}repos/{}/assignees?per_page=100'.format(api_url, repo_path)
        ):
            assignees = response.json()
            extraction_time = singer.utils.now()
            for assignee in assignees:
                assignee['_sdc_repository'] = repo_path
                with singer.Transformer(pre_hook=utf8_hook) as transformer:
                    rec = transformer.transform(assignee, schema, metadata=metadata.to_map(mdata))
                singer.write_record('assignees', rec, time_extracted=extraction_time)
                singer.write_bookmark(state, repo_path, 'assignees', {'since': singer.utils.strftime(extraction_time)})
                counter.increment()

    return state

def get_all_collaborators(schema, repo_path, state, mdata, _start_date):
    '''
    https://developer.github.com/v3/repos/collaborators/#list-collaborators
    '''
    with metrics.record_counter('collaborators') as counter:
        try:
            for response in authed_get_all_pages(
                    'collaborators',
                    '{}repos/{}/collaborators?per_page=100'.format(api_url, repo_path)
            ):
                collaborators = response.json()
                extraction_time = singer.utils.now()
                for collaborator in collaborators:
                    collaborator['_sdc_repository'] = repo_path
                    with singer.Transformer(pre_hook=utf8_hook) as transformer:
                        rec = transformer.transform(collaborator, schema, metadata=metadata.to_map(mdata))
                    singer.write_record('collaborators', rec, time_extracted=extraction_time)
                    singer.write_bookmark(state, repo_path, 'collaborator', {'since': singer.utils.strftime(extraction_time)})
                    counter.increment()
        except NotFoundException:
            logger.info('Received 404 not found while trying to access collaborators. You must' \
                    ' be a repo owner to view maintainers, skipping stream for repo {}.'\
                    .format(repo_path))
        except AuthException:
            logger.info('Received 403 unauthorized while trying to access collaborators. You must' \
                    ' have push access to load collaborators, skipping stream for repo {}.'\
                    .format(repo_path))

    return state


def create_patch_for_files(old_text, new_text):
    # Note: this patch may be slightly different from a patch generated with git since the diffing
    # algorithms aren't the same, but it will at least be correct and in the same format.

    newlineToken = '\\ No newline at end of file'
    # Add this random data too in the rare case where a file literally ends in the newlineToken but
    # does have a new line at the end.
    sentinal = "SDF1G5ALB3YU"
    newlineMarker = newlineToken + sentinal
    newlineMarkerLength = len(newlineMarker)

    # Also remove empty lines at end so that they aren't included in the diff output to get the
    # format to match git's patches.

    oldSplit = old_text.split('\n')
    if oldSplit[-1] != '':
        oldSplit[-1] += newlineMarker
    else:
        oldSplit = oldSplit[:-1]

    newSplit = new_text.split('\n')
    if newSplit[-1] != '':
        newSplit[-1] += newlineMarker
    else:
        newSplit = newSplit[:-1]

    # Patches don't use any when coming from the github API, so don't use nay here
    diff = difflib.unified_diff(oldSplit, newSplit, n=0)

    # Transform this to match the format of git patches coming from the API
    difflist = list(diff)
    newDiffList = []
    firstDiffFound = False
    for diffLine in difflist:
        # Skip lines before the first @@
        if diffLine[0:2] == '@@':
            firstDiffFound = True
        if not firstDiffFound:
            continue

        # Remove extra newlines after each diff line
        if diffLine[-1:] == '\n':
            newDiffList.append(diffLine[:-1])
        # If we found the newline marker at the end, remove it and add the newline token on the next
        # line like the diff format from github.
        elif diffLine[-newlineMarkerLength:] == newlineMarker:
            newDiffList.append(diffLine[:-newlineMarkerLength])
            newDiffList.append(newlineToken)
        else:
            newDiffList.append(diffLine)

    output = '\n'.join(newDiffList)
    return output

repo_cache = {}
def get_repo_metadata(repo_path):
    if not repo_path in repo_cache:
        for response in authed_get_all_pages(
                'branches',
                '{}repos/{}'.format(api_url, repo_path)
        ):
            repo_cache[repo_path] = response.json()
            # Will never be multiple pages
            break
    return repo_cache[repo_path]

BRANCH_CACHE = {}
def get_all_branches(schema, repo_path,  state, mdata, start_date):
    '''
    https://docs.github.com/en/rest/reference/repos#list-branches
    '''
    # No bookmark available

    default_branch_name = get_repo_metadata(repo_path)['default_branch']

    cur_cache = {}
    BRANCH_CACHE[repo_path] = cur_cache

    with metrics.record_counter('branches') as counter:
        for response in authed_get_all_pages(
                'branches',
                '{}repos/{}/branches?per_page=100'.format(api_url, repo_path)
        ):
            branches = response.json()
            extraction_time = singer.utils.now()
            for branch in branches:
                branch['_sdc_repository'] = repo_path
                branch['repo_name'] = repo_path + ':' + branch['name']
                isdefault = branch['name'] == default_branch_name
                branch['isdefault'] = isdefault

                cur_cache[branch['name']] = { 'sha': branch['commit']['sha'], \
                    'isdefault': isdefault, 'name': branch['name'] }
                with singer.Transformer() as transformer:
                    rec = transformer.transform(branch, schema, metadata=metadata.to_map(mdata))
                singer.write_record('branches', rec, time_extracted=extraction_time)
                counter.increment()
    return state

def get_all_heads_for_commits(repo_path):
    '''
    Gets a list of all SHAs to use as heads for importing lists of commits. Includes all branches
    and PRs (both base and head) as well as the main branch to get all potential starting points.
    '''
    default_branch_name = get_repo_metadata(repo_path)['default_branch']

    # If this data has already been populated with get_all_branches, don't duplicate the work.
    if not repo_path in BRANCH_CACHE:
        cur_cache = {}
        BRANCH_CACHE[repo_path] = cur_cache
        for response in authed_get_all_pages(
            'branches',
            '{}repos/{}/branches?per_page=100'.format(api_url, repo_path)
        ):
            branches = response.json()
            for branch in branches:
                isdefault = branch['name'] == default_branch_name
                cur_cache[branch['name']] = {
                    'sha': branch['commit']['sha'],
                    'isdefault': isdefault,
                    'name': branch['name']
                }

    if not repo_path in PR_CACHE:
        cur_cache = {}
        PR_CACHE[repo_path] = cur_cache
        for response in authed_get_all_pages(
            'pull_requests',
            '{}repos/{}/pulls?per_page=100&state=all'.format(api_url, repo_path)
        ):
            pull_requests = response.json()
            for pr in pull_requests:
                pr_num = pr.get('number')
                cur_cache[str(pr_num)] = {
                    'pr_num': str(pr_num),
                    'base_sha': pr['base']['sha'],
                    'base_ref': pr['base']['ref'],
                    'head_sha': pr['head']['sha'],
                    'head_ref': pr['head']['ref']
                }

    # Now build a set of all potential heads
    head_set = {}
    for key, val in BRANCH_CACHE[repo_path].items():
        head_set[val['sha']] = 'refs/heads/' + val['name']
    for key, val in PR_CACHE[repo_path].items():
        head_set[val['head_sha']] = 'refs/pull/' + val['pr_num'] + '/head'
        # There could be a PR into a branch that has since been deleted and this is our only record
        # of its head, so include it
        head_set[val['base_sha']] = 'refs/heads/' + val['base_ref']
    return head_set

# Diffs over this many bytes of text are dropped and instead replaced with a flag indicating that
# the file is large.
LARGE_FILE_DIFF_THRESHOLD = 1024 * 1024

def get_commit_detail_api(commit, repo_path):
    '''
    # Augment each commit with overall stats and file-level diff data by hitting the commits
    # endpoint with the individual commit hash.
    # This is copied from the github documentation:
    # Note: If there are more than 300 files in the commit diff, the response will
    # include pagination link headers for the remaining files, up to a limit of 3000
    # files. Each page contains the static commit information, and the only changes are
    # to the file listing.
    # TODO: if the changed file count exceeds 3000, then use the raw checkout to fetch
    # this data.
    '''

    # Hash of file addition that's too large, for testing
    #if commit['sha'] != '836f0c47362e2f92f57ddee977df0f5c0da6d53b':
    #    continue
    # Hash of commit with file change that's too large, for testing
    #if commit['sha'] != '1961e1b44e7c15b1f62f6da99b0e284b71d64048':
    #    continue

    commit['files'] = []
    for commit_detail in authed_get_all_pages(
        'commits',
        '{}repos/{}/commits/{}'.format(api_url, repo_path, commit['sha'])
    ):
        # TODO: test fetching multiple pages of changed files if the changed file count
        # exceeds 300.
        detail_json = commit_detail.json()
        commit['stats'] = detail_json['stats']
        commit['files'].extend(detail_json['files'])

    # Iterate through each of the file changes and fetch the raw patch if it is missing
    # because it is too big of a change
    for commitFile in commit['files']:
        commitFile['is_binary'] = False
        commitFile['is_large_patch'] = False

        # Skip if there's already a patch
        if 'patch' in commitFile:
            continue
        # If no changes are showing, this is probably a binary file
        if commitFile['changes'] == 0 and commitFile['additions'] == 0 and \
                commitFile['deletions'] == 0:
            # Indicate that this file is binary if it's "modified" and the change
            # counts are zero. Change counts can be zero for other reasons with renames
            # and additions/deletions of empty files.
            # Note: this will be wrong if there is a pure mode change
            if commitFile['status'] == 'modified':
                commitFile['is_binary'] = True
            continue

        # Patch is missing for large file, get the urls of the current and previous
        # raw change blobs
        currentContentsUrl = commitFile['contents_url']

        try:
            for currentContents in authed_get_all_pages(
                'file_contents',
                currentContentsUrl
            ):
                currentContentsJson = currentContents.json()
                fileContent = currentContentsJson['content']
                    # TODO: do we need to catch base64 decode errors in case file is binary?
                decodedFileContent = base64.b64decode(fileContent).decode("utf-8")
                # Will only be one page
                break

            # Get the previous contents if the file existed before (not added)
            decodedPreviousFileContent = ''
            if commitFile['status'] != 'added':
                contentPath = currentContentsUrl.split('?ref=')[0]
                # First parent is base, second parent is head
                baseSha = commit['parents'][0]['sha']
                if 'previous_filename' in commitFile:
                    contentPath = contentPath.replace(commitFile['filename'],
                        commitFile['previous_filename'])
                previousContentsUrl = contentPath + '?ref=' + baseSha

                for previousContents in authed_get_all_pages(
                    'file_contents',
                    previousContentsUrl
                ):
                    previousContentsJson = previousContents.json()
                    previousFileContent = previousContentsJson['content']
                    # TODO: do we need to catch base64 decode errors in case file is binary?
                    decodedPreviousFileContent = base64.b64decode(previousFileContent).decode("utf-8")
                    # Will only be one page
                    break

            patch = create_patch_for_files(decodedPreviousFileContent, decodedFileContent)
            if len(patch) > LARGE_FILE_DIFF_THRESHOLD:
                commitFile['is_large_patch'] = True
            else:
                commitFile['patch'] = patch
        except NotFoundException as err:
            logger.info('Encountered 404 while fetching blob. Flagging as large file and ' \
                'skipping. Original exception: ' + repr(err))
            commitFile['is_large_patch'] = True
        except AuthException as err:
            # Original error:
            # {'message': 'This API returns blobs up to 1 MB in size. The requested blob is too
            # large to fetch via the API, but you can use the Git Data API to request blobs up to
            # 100 MB in size.', 'errors': [{'resource': 'Blob', 'field': 'data', 'code':
            # 'too_large'}], 'documentation_url':
            # 'https://docs.github.com/rest/reference/repos#get-repository-content'}
            logger.info('Encountered 403 while fetching blob, which likely means it is too '\
                'large. Treating as large file and skipping. Original excpetion: ' + repr(err))
            commitFile['is_large_patch'] = True

def get_commit_detail_local(commit, repo_path, gitLocal):
    try:
        changes = gitLocal.getCommitDiff(repo_path, commit['sha'])
        commit['files'] = changes
    except Exception as e:
        # This generally shouldn't happen since we've already fetched and checked out the head
        # commit successfully, so it probably indicates some sort of system error. Just let it
        # bubbl eup for now.
        raise e

def get_commit_changes(commit, repo_path, useLocal, gitLocal):
    if useLocal:
        get_commit_detail_local(commit, repo_path, gitLocal)
    else:
        get_commit_detail_api(commit, repo_path)

        for commitFile in commit['files']:
            if 'added' == commitFile['status']:
                commitFile['changetype'] = 'add'
            elif 'removed' == commitFile['status']:
                commitFile['changetype'] = 'delete'
            # 'renamed' takes precedence over 'modified' in github, so we need to determine if there
            # was actually a change by looking at other fields.
            elif commitFile['additions'] > 0 or commitFile['deletions'] > 0 or \
                    commitFile['is_binary'] or commitFile['is_large_patch']:
                commitFile['changetype'] = 'edit'
            else:
                commitFile['changetype'] = 'none'
            commitFile['commit_sha'] = commit['sha']
    commit['_sdc_repository'] = repo_path
    commit['id'] = '{}/{}'.format(repo_path, commit['sha'])
    return commit

def get_all_commits(schema, repo_path,  state, mdata, start_date):
    '''
    https://developer.github.com/v3/repos/commits/#list-commits-on-a-repository
    '''

    # Get the set of all commits we have fetched previously
    fetchedCommits = get_bookmark(state, repo_path, "commits", "fetchedCommits")
    if not fetchedCommits:
        fetchedCommits = {}

    # We don't want newly fetched commits to update the state if we fail partway through, because
    # this could lead to commits getting marked as fetched when their parents are never fetched. So,
    # copy the dict.
    fetchedCommits = fetchedCommits.copy()

    # Get all of the branch heads to use for querying commits
    heads = get_all_heads_for_commits(repo_path)

    # Set this here for updating the state when we don't run any queries
    extraction_time = singer.utils.now()

    with metrics.record_counter('commits') as counter:
        for head in heads:
            # If the head commit has already been synced, then skip.
            if head in fetchedCommits:
                continue

            # Maintain a list of parents we are waiting to see
            missingParents = {}

            # We don't want to use a time-based bookmark becuase it could skip commits
            # that are pushed after they are committed. Using only the fetchedCommits as
            # our bookmark.
            cururl = '{}repos/{}/commits?per_page=100&sha={}' \
                .format(api_url, repo_path, head)
            pagenum = 0
            while True:
                # Get commits one page at a time
                try:
                    response = list(authed_get_yield('commits', cururl))[0]
                except InternalServerError as err:
                    if pagenum != 0:
                        raise err

                    # So this can happen when the sha isn't found, but correctly produces a 404
                    # when stripping off the per-page and since
                    cururl = '{}repos/{}/commits?sha={}' \
                        .format(api_url, repo_path, head)
                    logger.warning('Received internal server error at commits endpoint for sha ' +\
                        '{}, retrying without page limit'.format(head))
                    continue
                except NotFoundException as err:
                    if pagenum != 0:
                        raise err
                    # Some commits may just not exist. This has happened for at least one PR base
                    # sha for a PR that was closed on a deleted branch from a repo that was copied
                    # over from github enterprise (not sure if the last part has anything to do with
                    # it). So, just skip this head, mark the commit as fetched, and continue.
                    fetchedCommits[head] = -1
                    logger.warning('Commit {} not found for head {}'.format(head, heads[head]))
                    break

                pagenum += 1

                commits = response.json()
                extraction_time = singer.utils.now()
                for commit in commits:
                    # Skip commits we've already imported
                    if commit['sha'] in fetchedCommits:
                        continue
                    commit['_sdc_repository'] = repo_path
                    commit['id'] = '{}/{}'.format(repo_path, commit['sha'])
                    with singer.Transformer() as transformer:
                        rec = transformer.transform(commit, schema, metadata=metadata.to_map(mdata))
                    singer.write_record('commits', rec, time_extracted=extraction_time)

                    # Record that we have now fetched this commit
                    fetchedCommits[commit['sha']] = 1
                    # No longer a missing parent
                    missingParents.pop(commit['sha'], None)

                    # Keep track of new missing parents
                    for parent in commit['parents']:
                        if not parent['sha'] in fetchedCommits:
                            missingParents[parent['sha']] = 1
                    counter.increment()

                # If there are no missing parents, then we are done prior to reaching the lst page
                if not missingParents:
                    break
                elif 'next' in response.links:
                    cururl = response.links['next']['url']
                else:
                    # If we have reached the end of our data but not found the parents
                    # We can try to get those commits directly from Github
                    missing_parent_sha = list(missingParents.keys())[0]
                    newurl = '{}repos/{}/commits/{}' \
                        .format(api_url, repo_path, missing_parent_sha)

                    # We did not find the commits referencing the sha directly
                    # we have problems
                    # this is a bit of a safety net as we should throw on a
                    # NotFoundException if the sha wasn't found
                    if cururl == newurl:
                        raise GithubException('Some commit parents never found: ' + \
                            ','.join(missingParents.keys()))

                    cururl = newurl

    # Don't write until the end so that we don't record fetchedCommits if we fail and never get
    # their parents.
    singer.write_bookmark(state, repo_path, 'commits', {
        'fetchedCommits': fetchedCommits
    })

    return state

async def getChangedfilesForCommits(commits, repo_path, hasLocal, gitLocal):
    coros = []
    for commit in commits:
        changesCoro = asyncio.to_thread(get_commit_changes, commit, repo_path, hasLocal, gitLocal)
        coros.append(changesCoro)
    results = await asyncio.gather(*coros)
    return results

def get_all_commit_files(schemas, repo_path,  state, mdata, start_date, gitLocal):
    # Get the set of all commits we have fetched previously
    fetchedCommits = get_bookmark(state, repo_path, "commit_files", "fetchedCommits")
    if not fetchedCommits:
        fetchedCommits = {}

    # We don't want to use a time-based bookmark becuase it could skip commits
    # that are pushed after they are committed. So, set the bookmark to the beginning
    # of time until we have everything, using only the fetchedCommits bookmark.
    bookmark = '1970-01-01'

    logger.info('Found {} fetched commits in state.'.format(len(fetchedCommits)))

    # We don't want newly fetched commits to update the state if we fail partway through, because
    # this could lead to commits getting marked as fetched when their parents are never fetched. So,
    # copy the dict.
    fetchedCommits = fetchedCommits.copy()

    # Get all of the branch heads to use for querying commits
    #heads = get_all_heads_for_commits(repo_path)
    heads = gitLocal.getAllHeads(repo_path)

    # Set this here for updating the state when we don't run any queries
    extraction_time = singer.utils.now()

    count = 0
    # The lage majority of PRs are less than this many commits
    LOG_PAGE_SIZE = 10000
    with metrics.record_counter('commit_files') as counter:
        # First, walk through all the heads and queue up all the commits that need to be imported
        commitQ = []

        for headRef in heads:
            count += 1
            if count % 10 == 0:
                process = psutil.Process(os.getpid())
                logger.info('Processed heads {}/{}, {} bytes'.format(count, len(heads),
                    process.memory_info().rss))
            headSha = heads[headRef]
            # If the head commit has already been synced, then skip.
            if headSha in fetchedCommits:
                #logger.info('Head already fetched {} {}'.format(headRef, headSha))
                continue

            # Emit the ref record as well
            refRecord = {
                'id': '{}/{}'.format(repo_path, headRef),
                '_sdc_repository': repo_path,
                'ref': headRef,
                'sha': headSha
            }
            with singer.Transformer() as transformer:
                rec = transformer.transform(refRecord, schemas['refs'],
                    metadata=metadata.to_map(mdata))
            singer.write_record('refs', rec, time_extracted=extraction_time)

            # Maintain a list of parents we are waiting to see
            missingParents = {}

            # Verify that this commit exists in our mirrored repo
            hasLocal = gitLocal.hasLocalCommit(repo_path, headSha)
            if not hasLocal:
                logger.warning('MISSING REF/COMMIT {}/{}/{}'.format(repo_path, headRef, headSha))
                # Skip this now that we're mirroring everything. We shouldn't have anything that's
                # missing from github's API
                continue

            cururl = '{}repos/{}/commits?per_page=100&sha={}&since={}' \
                .format(api_url, repo_path, headSha, bookmark)
            offset = 0
            newlyFetchedCommits = {}
            while True:
                # Get commits one page at a time
                if hasLocal:
                    commits = gitLocal.getCommitsFromHeadPyGit(repo_path, headSha,
                        limit = LOG_PAGE_SIZE, offset = offset, skipAtCommits=fetchedCommits)
                else:
                    response = list(authed_get_yield('commits', cururl))[0]
                    commits = response.json()
                extraction_time = singer.utils.now()
                for commit in commits:
                    # Skip commits we've already imported
                    if commit['sha'] in fetchedCommits or commit['sha'] in newlyFetchedCommits:
                        continue

                    commitQ.append(commit)

                    # Record that we have now fetched this commit
                    newlyFetchedCommits[commit['sha']] = 1
                    # No longer a missing parent
                    missingParents.pop(commit['sha'], None)

                    # Keep track of new missing parents
                    for parent in commit['parents']:
                        if not parent['sha'] in fetchedCommits and not parent['sha'] in newlyFetchedCommits:
                            missingParents[parent['sha']] = 1

                # If there are no missing parents, then we are done prior to reaching the lst page
                if not missingParents:
                    break
                elif not hasLocal and 'next' in response.links:
                    cururl = response.links['next']['url']
                elif hasLocal and len(commits) > 0:
                    offset += LOG_PAGE_SIZE
                # Else if we have reached the end of our data but not found the parents, then we
                # have a problem
                else:
                    raise GithubException('Some commit parents never found: ' + \
                        ','.join(missingParents.keys()))

            # After successfully processing all commits for this head, add them to fetchedCommits
            fetchedCommits.update(newlyFetchedCommits)

        # Now run through all the commits in parallel
        gc.collect()
        process = psutil.Process(os.getpid())
        logger.info('Processing {} commits, mem(mb) {}'.format(len(commitQ),
            process.memory_info().rss / (1024 * 1024)))

        # Run in batches
        i = 0
        BATCH_SIZE = 2
        PRINT_INTERVAL = 8
        hasLocal = True # Only local now
        totalCommits = len(commitQ)
        finishedCount = 0

        while len(commitQ) > 0:
            # Slice off the queue to avoid memory leaks
            curQ = commitQ[0:BATCH_SIZE]
            commitQ = commitQ[BATCH_SIZE:]
            logger.info('getChangedFilesForCommits -- [{}]'.format([c['sha'] for c in curQ]))
            changedFileList = asyncio.run(getChangedfilesForCommits(curQ, repo_path, hasLocal,
                gitLocal))
            for commitfiles in changedFileList:
                with singer.Transformer() as transformer:
                    rec = transformer.transform(commitfiles, schemas['commit_files'],
                        metadata=metadata.to_map(mdata))
                counter.increment()
                singer.write_record('commit_files', rec, time_extracted=extraction_time)

            finishedCount += BATCH_SIZE
            if i % (BATCH_SIZE * PRINT_INTERVAL) == 0:
                curQ = None
                changedFileList = None
                gc.collect()
                process = psutil.Process(os.getpid())
                logger.info('Imported {}/{} commits, {}/{} MB'.format(finishedCount, totalCommits,
                    process.memory_info().rss / (1024 * 1024),
                    process.memory_info().data / (1024 * 1024)))


    # Don't write until the end so that we don't record fetchedCommits if we fail and never get
    # their parents.
    singer.write_bookmark(state, repo_path, 'commit_files', {
        'fetchedCommits': fetchedCommits
    })

    return state

def get_all_issues(schema, repo_path,  state, mdata, start_date):
    '''
    https://developer.github.com/v3/issues/#list-issues-for-a-repository
    '''

    bookmark = get_bookmark(state, repo_path, "issues", "since", start_date)
    if bookmark:
        query_string = '&since={}'.format(bookmark)
    else:
        query_string = ''

    with metrics.record_counter('issues') as counter:
        for response in authed_get_all_pages(
                'issues',
                '{}repos/{}/issues?per_page=100&state=all&sort=updated&direction=asc{}'.format(api_url, repo_path, query_string)
        ):
            issues = response.json()
            extraction_time = singer.utils.now()
            for issue in issues:
                issue['_sdc_repository'] = repo_path
                if issue.get('assignee') is None and issue.get('assignees') is not None and len(issue.get('assignees')) > 0:
                    issue['assignee'] = issue.get('assignees')[0]

                with singer.Transformer(pre_hook=utf8_hook) as transformer:
                    rec = transformer.transform(issue, schema, metadata=metadata.to_map(mdata))
                singer.write_record('issues', rec, time_extracted=extraction_time)
                singer.write_bookmark(state, repo_path, 'issues', {'since': singer.utils.strftime(extraction_time)})
                counter.increment()
    return state

def get_all_comments(schema, repo_path, state, mdata, start_date):
    '''
    https://developer.github.com/v3/issues/comments/#list-comments-in-a-repository

    TODO: There seems to a limit of 40,000 commments for this endpoint. Instead, get the comments
    associated with each individual issues.
    '''

    bookmark = get_bookmark(state, repo_path, "comments", "since", start_date)
    if bookmark:
        query_string = '&since={}'.format(bookmark)
    else:
        query_string = ''

    with metrics.record_counter('comments') as counter:
        for response in authed_get_all_pages(
                'comments',
                '{}repos/{}/issues/comments?per_page=100&sort=updated' \
                '&direction=asc{}'.format(api_url, repo_path, query_string)
        ):
            comments = response.json()
            extraction_time = singer.utils.now()
            for comment in comments:
                comment['_sdc_repository'] = repo_path
                with singer.Transformer(pre_hook=utf8_hook) as transformer:
                    rec = transformer.transform(comment, schema, metadata=metadata.to_map(mdata))
                singer.write_record('comments', rec, time_extracted=extraction_time)
                singer.write_bookmark(state, repo_path, 'comments', {'since': singer.utils.strftime(extraction_time)})
                counter.increment()
    return state

def get_all_stargazers(schema, repo_path, state, mdata, _start_date):
    '''
    https://developer.github.com/v3/activity/starring/#list-stargazers

    NOTE: This endpoint is limited to a maximum of 40,000 rows.
    '''

    stargazers_headers = {'Accept': 'application/vnd.github.v3.star+json'}

    with metrics.record_counter('stargazers') as counter:
        for response in authed_get_all_pages(
                'stargazers',
                '{}repos/{}/stargazers?per_page=100'.format(api_url, repo_path), stargazers_headers
        ):
            stargazers = response.json()
            extraction_time = singer.utils.now()
            for stargazer in stargazers:
                user_id = stargazer['user']['id']
                stargazer['_sdc_repository'] = repo_path
                with singer.Transformer(pre_hook=utf8_hook) as transformer:
                    rec = transformer.transform(stargazer, schema, metadata=metadata.to_map(mdata))
                rec['user_id'] = user_id
                singer.write_record('stargazers', rec, time_extracted=extraction_time)
                singer.write_bookmark(state, repo_path, 'stargazers', {'since': singer.utils.strftime(extraction_time)})
                counter.increment()

    return state

def get_repository_data(schema, repo_path, state, mdata, _start_date):
    global fetch_forks

    repo_metadata = repo_cache.get(repo_path, None)

    if not repo_metadata or (repo_metadata.get('fork', False) == True and fetch_forks):
        if not repo_metadata:
            logger.info('Repo cache not hydrated, must fetch details')
        elif repo_metadata.get('fork', False):
            logger.info('Repo is fork, must fetch details')

        try:
            repo_metadata = authed_get(
                'repositories',
                '{}repos/{}'.format(api_url, repo_path)
            ).json()
            repo_cache[repo_path] = repo_metadata
        except GithubException as ex:
            # if Github has blocked access to a repo because of their tos or dmca, we can ignore it and proceed
            if isinstance(ex, UnavailableForLegalReasonsError):
                logger.warn('Github repository {} not available for legal reasons'.format(repo_path))
                return
            elif ex.server_response and ex.server_response['message'] == 'Repository access blocked' \
                and ex.server_response['block'] and ex.server_response['block']['reason'] in ['tos', 'dmca']:
                logger.warn('Github blocked access to {} because of {}, skipping'.format(repo_path, ex.server_response['block']['reason']))
                return
            else:
                raise ex

    fork_org_name = None
    fork_repo_name = None
    if repo_metadata['fork'] and repo_metadata.get('parent', {}).get('full_name', False):
        fork_split = repo_metadata['parent']['full_name'].split('/')
        fork_org_name = fork_split[0]
        fork_repo_name = fork_split[1]

    with metrics.record_counter('repositories') as counter:
        extraction_time = singer.utils.now()
        repo = {}
        repo['id'] = 'github:' + repo_path
        repo['source'] = 'github'
        repo['org_name'] = repo_path.split('/')[0]
        repo['repo_name'] = repo_path.split('/')[1]
        repo['is_source_public'] = repo_metadata['visibility'] == 'public'
        repo['fork_org_name'] = fork_org_name
        repo['fork_repo_name'] = fork_repo_name
        repo['description'] = repo_metadata['description']
        repo['is_fork'] = repo_metadata.get('fork', None)
        with singer.Transformer() as transformer:
            rec = transformer.transform(repo, schema, metadata=metadata.to_map(mdata))
        singer.write_record('repositories', rec, time_extracted=extraction_time)
        counter.increment()
    return state

def get_selected_streams(catalog):
    '''
    Gets selected streams.  Checks schema's 'selected'
    first -- and then checks metadata, looking for an empty
    breadcrumb and mdata with a 'selected' entry
    '''
    selected_streams = []
    for stream in catalog['streams']:
        stream_metadata = stream['metadata']
        if stream['schema'].get('selected', False):
            selected_streams.append(stream['tap_stream_id'])
        else:
            for entry in stream_metadata:
                # stream metadata will have empty breadcrumb
                if not entry['breadcrumb'] and entry['metadata'].get('selected',None):
                    selected_streams.append(stream['tap_stream_id'])

    return selected_streams

def get_stream_from_catalog(stream_id, catalog):
    for stream in catalog['streams']:
        if stream['tap_stream_id'] == stream_id:
            return stream
    return None

SYNC_FUNCTIONS = {
    'branches': get_all_branches,
    'commits': get_all_commits,
    'commit_files': get_all_commit_files,
    'comments': get_all_comments,
    'issues': get_all_issues,
    'assignees': get_all_assignees,
    'collaborators': get_all_collaborators,
    'pull_requests': get_all_pull_requests,
    'releases': get_all_releases,
    'stargazers': get_all_stargazers,
    'events': get_all_events,
    'issue_events': get_all_issue_events,
    'issue_milestones': get_all_issue_milestones,
    'issue_labels': get_all_issue_labels,
    'projects': get_all_projects,
    'commit_comments': get_all_commit_comments,
    'repositories': get_repository_data,
    'teams': get_all_teams,
    'projects_v2': get_all_projects_v2,
    'projects_v2_issues': get_all_projects_v2_issues,
    'code_coverage': get_all_code_coverage,
    'workflows': get_all_workflows,
    'workflow_runs': get_all_workflow_runs,
    'deployments': get_all_deployments,
}

SUB_STREAMS = {
    'pull_requests': ['reviews', 'review_comments'],
    'projects': ['project_cards', 'project_columns'],
    'teams': ['team_members', 'team_memberships'],
    'commit_files': ['refs'],
    'workflow_runs': ['workflow_run_jobs'],
    'deployments': ['deployment_statuses']
}

schema_cache = {}
def write_schema(stream_id, stream_schema, stream_key_properties):
    if stream_id not in schema_cache:
        singer.write_schema(stream_id, stream_schema, stream_key_properties)
        schema_cache[stream_id] = True
    return None

def do_sync(config, state, catalog):
    global process_globals
    global code_coverage_artifact_name
    global api_url
    global graphql_url
    global fetch_forks

    logger.info(f'config: {json.dumps(config)}')
    start_date = config['start_date'] if 'start_date' in config else None

    # optionally override the default for processing global stream data (e.g. teams)
    if 'process_globals' in config:
        process_globals = config['process_globals']

    # optionally override the default code coverage artifact name
    if 'code_coverage_artifact_name' in config:
        code_coverage_artifact_name = config['code_coverage_artifact_name']
    api_url = 'https://api.github.com/'
    if 'base_url' in config:
        api_url = config['base_url']
        if api_url[-1] != '/':
            api_url += '/'
        logger.info('Using GitHub API URL {}'.format(api_url))

    graphql_url = f'{api_url}graphql'
    if 'graphql_url' in config:
        graphql_url = config['graphql_url']
        logger.info('Using Github GraphQL URL {}'.format(graphql_url))

    logger.info('Process globals = {}'.format(str(process_globals)))

    fetch_forks = config.get('fetch_forks', True)

    # get selected streams, make sure stream dependencies are met
    selected_stream_ids = get_selected_streams(catalog)
    validate_dependencies(selected_stream_ids)

    # Expand */* into the full list of orgs (e.g minwareco/*, otherorg/*)
    if config['repository'] == '*/*':
        if not config['access_token'] or len(config['access_token']) == 0:
            raise Exception('Cannot use org wildcard without a PAT (access_token).')
        access_token = set_auth_headers(config)
        repositories = list()
        orgs = getOrgs()
        for org in orgs:
            repositories.append(f'{org}/*')
    else:
        repositories = list(filter(None, config['repository'].split(' ')))

    if 'exclude_repositories' in config:
        excludeSplit = config['exclude_repositories'].split(' ')
    else:
        excludeSplit = []

    # Expand org/*
    allRepos = []
    for repo in repositories:
        repoSplit = repo.split('/')
        if len(repoSplit) < 2:
            logger.error('Invalid repository format: %s', repo)
            sys.exit(1)
        if repoSplit[1] == '*':
            org = repoSplit[0]
            access_token = set_auth_headers(config, org)
            orgRepos = getReposForOrg(repoSplit[0])
            orgRepos = [r for r in orgRepos if r not in excludeSplit]
            allRepos.extend(orgRepos)
        else:
            if repo not in excludeSplit:
                allRepos.append(repo)

    state = translate_state(state, catalog, allRepos)

    # Put branches and then pull requests before commits, which have a data dependency on them.
    # Put projects_v2 before projects_v2_issues since the latter is dependent on former.
    def schemaSortFunc(val):
        if val['tap_stream_id'] == 'branches':
            return 'a1'
        elif val['tap_stream_id'] == 'pull_requests':
            return 'a2'
        elif val['tap_stream_id'] == 'commits':
            return 'a3'
        elif val['tap_stream_id'] == 'projects_v2':
            return 'a4'
        elif val['tap_stream_id'] == 'projects_v2_issues':
            return 'a5'
        else:
            return val['tap_stream_id']
    catalog['streams'].sort(key=schemaSortFunc)

    #pylint: disable=too-many-nested-blocks
    for repo in allRepos:
        logger.info("Starting sync of repository: %s", repo)

        org = repo.split('/')[0]
        access_token = set_auth_headers(config, org)

        if 'skip_unavailable' in config and bool(config['skip_unavailable']):
            try:
                get_repo_metadata(repo)
            except:
                logger.warning(f'{repo} is not available, skipping')
                continue

        gitLocal = GitLocal({
            'access_token': access_token,
            'workingDir': '/tmp'
        }, 'https://x-access-token:{}@github.com/{}.git',
            config['hmac_token'] if 'hmac_token' in config else None,
            logger=logger)

        for stream in catalog['streams']:
            stream_id = stream['tap_stream_id']
            stream_schema = stream['schema']
            mdata = stream['metadata']

            # if it is a "sub_stream", it will be sync'd by its parent
            if not SYNC_FUNCTIONS.get(stream_id):
                continue

            # if stream is selected, write schema and sync
            if stream_id in selected_stream_ids:
                logger.info("Syncing stream: %s", stream_id)
                write_schema(stream_id, stream_schema, stream['key_properties'])

                # get sync function and any sub streams
                sync_func = SYNC_FUNCTIONS[stream_id]
                sub_stream_ids = SUB_STREAMS.get(stream_id, None)

                # sync stream
                if not sub_stream_ids:
                    state = sync_func(stream_schema, repo, state, mdata, start_date)

                # handle streams with sub streams
                else:
                    stream_schemas = {stream_id: stream_schema}

                    # get and write selected sub stream schemas
                    for sub_stream_id in sub_stream_ids:
                        if sub_stream_id in selected_stream_ids:
                            sub_stream = get_stream_from_catalog(sub_stream_id, catalog)
                            stream_schemas[sub_stream_id] = sub_stream['schema']
                            write_schema(sub_stream_id, sub_stream['schema'],
                                                sub_stream['key_properties'])

                    # sync stream and its sub streams
                    if stream_id == 'commit_files':
                        state = sync_func(stream_schemas, repo, state, mdata, start_date,
                            gitLocal)
                    else:
                        state = sync_func(stream_schemas, repo, state, mdata, start_date)
        # Write the state after each repo. There use to be a check for:
        #   stream_id != 'branches' and stream_id != 'pull_requests'
        # to avoid saving the state after branches or pull_requests and having a data dependency on
        # commits reading from their output, but that's no longer necessary that we wait for the
        # whole repo to process.
        # The reason for writing only after the whole repo is that the state size can get pretty
        # big, which will end up exhausting memory in the target due to buffering those state lines
        # while it is waiting for a certain amount of data to arrive.
        # In the future, we should take a two-pronged appraoch to fixing this of both (1) reducing
        # the size of the state itself, and (2) forking and modifying the postgres target to count
        # the size of the state it is buffering as part of its memory limits, which it's not doing
        # right now and running out of memory as a result.
        singer.write_state(state)



def main():
    global latest_response
    global latest_request
    
    args = singer.utils.parse_args(REQUIRED_CONFIG_KEYS)
    if args.config and 'access_token' in args.config:
        logger.addToken(args.config['access_token'])
        
    try:
        if args.discover:
            do_discover(args.config)
        else:
            catalog = args.properties if args.properties else get_catalog()
            do_sync(args.config, args.state, catalog)
    except BadCredentialsException as exc:
        logger.critical("Authentication Error: Invalid GitHub credentials.")
        logger.critical("If you are using a Personal Access Token (PAT), please verify it is valid and has the required permissions.")
        logger.critical("Error details: %s", str(exc))
        if latest_response and latest_request:
            logger.critical('Latest Request URL: {}'.format(latest_request['url']))
            logger.critical('Response Code: {}'.format(latest_response.status_code))
        sys.exit(1)
    except AuthException as exc:
        logger.critical("GitHub App Authentication Error: %s", str(exc))
        logger.critical("If you are trying to use GitHub App authentication, please verify your app_id and app_pem are correctly configured.")
        logger.critical("If you intended to use a Personal Access Token (PAT), make sure it is provided in the config as 'access_token'.")
        sys.exit(1)
    except Exception as exc:
        for line in traceback.format_exc().splitlines():
            logger.critical(line)
        if latest_response and latest_request:
            logger.critical('Latest Request URL: {}'.format(latest_request['url']))
            logger.critical('Response Code: {}'.format(latest_response.status_code))
            logger.critical('Response Data:')
            # this is different than the abovce so that logger can get this as valid json and remove data from sensitive fields
            logger.critical(latest_response.text)

        sys.exit(1)

if __name__ == "__main__":
    main()
