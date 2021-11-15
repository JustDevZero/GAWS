import argparse
import datetime
import logging
import logging.handlers
import os
import re
import shlex
import shutil
import subprocess
import sys
from configparser import ConfigParser
from copy import deepcopy
from getpass import getpass
from pathlib import Path
from xml.etree import cElementTree as ET

import aws_google_auth
import botocore
import botocore.session
import keyring
from botocore.exceptions import EndpointConnectionError

EMAIL_REGEXP = re.compile(r'(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)')

AWS_REGIONS = [
    'us-east-2',
    'us-east-1',
    'us-west-1',
    'us-west-2',
    'us-gov-west-1',
    'us-gov-east-1',
    'af-south-1',
    'ap-east-1',
    'ap-south-1',
    'ap-northeast-3',
    'ap-northeast-2',
    'ap-southeast-1',
    'ap-southeast-2',
    'ap-northeast-1',
    'ca-central-1',
    'eu-central-1',
    'eu-west-1',
    'eu-west-2',
    'eu-south-1',
    'eu-west-3',
    'eu-north-1',
    'me-south-1',
    'sa-east-1'
]


def ResolvePath(path_route):
    return Path(path_route).expanduser().resolve()


def Config(path_route):
    path = ResolvePath(path_route)
    if not path.exists():
        raise argparse.ArgumentTypeError(f'{path_route} not found')
    parser = ConfigParser()
    try:
        parser.read(path)
        return parser
    except BaseException:
        raise argparse.ArgumentTypeError(f'{path_route} is not a valid ini file.')

def Preference(path_route):
    path = ResolvePath(path_route)
    if not path.exists():
        return path
    parser = ConfigParser()
    try:
        parser.read(path)
        return path
    except BaseException:
        raise argparse.ArgumentTypeError(f'{path_route} is not a valid ini file.')


def is_valid_region(region_name):
    region_name = region_name or ''
    region_name = region_name.lower()
    return region_name in AWS_REGIONS


def ValidRegionParam(region_name):
    if not is_valid_region(region_name):
        raise argparse.ArgumentTypeError(f'{region_name} region')
    return region_name.lower()


def is_true(data):
    if not data or data.strip():
        return False
    data = data.strip().upper()
    return data in ['YES', 'Y']

def try_int(value):
    try:
        return int(value)
    except BaseException:
        return 0

def is_valid_email(value):
    try:
        matches = EMAIL_REGEXP.search(value)
        return matches and matches.groups()
    except BaseException:
        return False

class EnvironProxy:
    __slots__ = ('_original_environ',)
    env = {}

    def __init__(self):
        self._original_environ = os.environ

    def __enter__(self):
        self._original_environ = os.environ
        os.environ = self
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        os.environ = self._original_environ

    def __getitem__(self, item):
        try:
            return self._original_environ[item]
        except KeyError:
            return ''


def expandvars(path):
    replacer = '\0'  # NUL shouldn't be in a file path anyways.
    while replacer in path:
        replacer *= 2

    path = path.replace('\\$', replacer)

    with EnvironProxy():
        return os.path.expandvars(path).replace(replacer, '$')


AWS_DEFAULT_DURATION = try_int(os.environ.get('AWS_DEFAULT_DURATION')) or 3200


class IssueInstantException(Exception):
    pass


class GAWS:

    _keyring_namespace = 'aws-google-auth'
    command = None
    clients = []
    log = None
    google_auth_bin = None
    preferences = None
    default_role = None
    default_user = None
    default_region = None
    default_sso_region = None
    previous_account_id = None
    previous_sp_id = None
    previous_role = None
    previous_user = None
    previous_idp_id = None
    default_idp_id = None
    default_sp_id = None
    default_account = None
    default_password = None

    def __init__(self) -> None:
        handler = logging.StreamHandler(sys.stdout)
        self.__boto_session = botocore.session.Session()
        self.log = logging.getLogger('gaws')
        self.log.addHandler(handler)
        parser = argparse.ArgumentParser()
        parser.add_argument('--gaws-file', '-g', default='./gaws.ini', type=Config, dest='gaws_content', required=False, help='gaws.ini of the project')
        parser.add_argument('--log', '-l', type=ResolvePath, dest='log_file', required=False)
        parser.add_argument('--sp-id', '-S', type=str, dest='sp_id', required=False, help='The SP_ID from the Google SAML SSO')
        parser.add_argument('--idp-id', '-I', type=str, dest='idp_id', required=False, help='The IDP_ID from the Google SAML SSO')
        parser.add_argument('--user', '-u', type=str, dest='user', required=False, help='Your default gmail user')
        parser.add_argument('--account', '-a', type=str, dest='default_account', required=False, help='Your default aws account')
        parser.add_argument('--region', '-r', type=ValidRegionParam, dest='default_region', required=False, help='Your default aws region')
        parser.add_argument('--sso-region', '-s', type=ValidRegionParam, dest='default_sso_region', required=False, help='Your default sso region')
        parser.add_argument('--role', '-R', type=str, dest='default_role', required=False, help='Your default role')
        parser.add_argument('--duration', '-D', type=int, dest='duration', required=False, default=AWS_DEFAULT_DURATION)
        parser.add_argument('--use-profiles', dest="inject_profile", action='store_true', help='Use profiles instead of overwriting "default"')
        parser.add_argument('--append-region', dest="append_region", action='store_true', help='Inject a --region parameter dynamically, usefull for things such as AWS SAM.')
        parser.add_argument('--preferences', '-p', type=Preference, dest='preference_file', default='~/.gaws/config.ini', required=False, help="""
        This is where gaws will store the default values.
        """)
        parser.add_argument('--resolve-aliases', dest="resolve_aliases", action='store_true')
        parser.add_argument('--no-cache', dest="store_cache", action='store_false')
        parser.add_argument('--client', '-c', action='append', type=str, dest='clients', help="Can be used multiple times to some clients instead of all.")
        parser.add_argument('--all-clients', dest="all_clients", action='store_true')
        # parser.add_argument('--nuke', '-n', dest="nuke", action='store_true')
        parser.add_argument('--expand-vars', '-e', dest="expandvars", action='store_true', help="Expand bash variables instead of showing them.")
        group = parser.add_mutually_exclusive_group()
        group.add_argument('--quiet', '-q', dest="quiet", action='store_true')
        group.add_argument('--debug', '-d', dest="debug", action='store_true')
        self.args, self.command = parser.parse_known_args()
        if self.args.debug:
            self.log.setLevel(logging.DEBUG)
        else:
            self.log.setLevel(logging.WARN)

        self.google_auth_bin = shutil.which('aws-google-auth')
        if not self.google_auth_bin:
            exit('aws-google-auth not found, please visit https://pypi.org/project/aws-google-auth/ to learn how to install it.')

        preference_parser = ConfigParser()

        if not self.args.preference_file.exists():
            self.preference_wizard()

        while self.preferences is None:
            try:
                preference_parser.read(self.args.preference_file)
                self.preferences = preference_parser
            except BaseException:
                self.preference_wizard()

        self.default_password = None
        self.default_idp_id = self.args.idp_id or self.preferences.get('gaws', 'idp_id', fallback=None)
        self.default_sp_id = self.args.sp_id or self.preferences.get('gaws', 'sp_id', fallback=None)
        self.default_region = self.args.default_region or self.preferences.get('gaws', 'region', fallback=None)
        self.default_region = self.default_region if self.default_region else None
        self.default_sso_region = self.args.default_sso_region or self.preferences.get('gaws', 'sso_region', fallback=None)
        self.default_sso_region = self.default_sso_region if self.default_sso_region else None
        self.default_account = self.args.default_account or self.preferences.get('gaws', 'account', fallback=None)
        self.default_role = self.args.default_role or self.preferences.get('gaws', 'role_name', fallback=None)
        self.default_duration = try_int(self.args.duration or self.preferences.get('gaws', 'duration', fallback=None))
        self.default_duration = self.default_duration if self.default_duration > 0 else AWS_DEFAULT_DURATION
        self.default_user = self.preferences.get('gaws', 'user', fallback=None)

        if self.args.user and is_valid_email(self.args.user):
            self.default_user = self.args.user

        if self.default_user and not is_valid_email(self.default_user):
            self.default_user = None

        if self.default_user:
            self.default_password = self.get_password(self.default_user)

        if self.default_password is None and self.default_user:
            self.log.info("Default password not found.")
            self.default_password = getpass(f'Enter password for Google Account ({self.default_user}):')
            self.set_password(self.default_user, self.default_password)

        non_existent_clients = []

        _clients = self.args.gaws_content.sections()

        if not _clients:
            exit('No client found on gaws.ini')

        if not self.args.clients and not self.args.all_clients:
            exit('To avoid oopsies, you need to specify a list of clients, example: --client client1 --client client2 or be brave and use --all-clients.')

        search_clients = self.args.clients
        if self.args.all_clients:
            search_clients = _clients

        non_existent_clients = [x for x in search_clients if x not in _clients]
        self.clients = [x for x in search_clients if x in _clients]

        if non_existent_clients:
            non_str = ', '.join(non_existent_clients)
            exit(f'The clients {non_str} are not on the ini file.')

        if self.args.log_file:
            if not self.args.log_file.parent.exists():
                try:
                    self.args.log_file.parent.mkdir(parents=True)
                except BaseException:
                    pass
            try:
                handler = logging.handlers.RotatingFileHandler(str(self.args.log_file))
                self.log.addHandler(handler)
            except BaseException:
                self.log.error('Not able to store the logs, showing them on screen.')

    @property
    def credentials_file(self):
        return os.path.expanduser(self.__boto_session.get_config_variable('credentials_file'))

    def saml_cache_file(self, idp_id):
        return Path(self.credentials_file.replace('credentials', f'saml_cache_%{idp_id}.xml'))

    def preference_wizard(self):

        while not self.default_user:
            self.default_user = input('Enter your default Google Account:\n')
            self.default_user = self.default_user.strip()

        while self.default_password is None:
            self.default_password = getpass(f'Enter password for Google Account ({self.default_user}):\n')

        while not self.default_idp_id:
            self.default_idp_id = input('Enter your Google SAML/SSO IDP_ID:\n')
            self.default_idp_id = self.default_idp_id.strip()

        while not self.default_sp_id:
            self.default_sp_id = input('Enter your Google SAML/SSO SP_ID:\n')
            self.default_sp_id = self.default_sp_id.strip()

        while not self.default_region:
            self.default_region = input('Enter default region:\n')
            self.default_region = self.default_region.strip() or ''
            self.default_region = self.default_region.lower()
            if not is_valid_region(self.default_region):
                self.default_region = None

        while not self.default_sso_region:
            self.default_sso_region = input(f'Enter default SSO region (default "{self.default_region}"):\n')
            self.default_sso_region = self.default_sso_region.strip() or ''
            self.default_sso_region = self.default_sso_region.lower() or self.default_region
            if not is_valid_region(self.default_sso_region):
                self.default_sso_region = None

        while not self.default_account:
            self.default_account = input('Enter default account:\n')
            self.default_account = self.default_account.strip()

        self.preferences = ConfigParser()

        self.preferences['gaws'] = {
            'idp_id': self.default_idp_id,
            'sp_id': self.default_sp_id,
            'region': self.default_region,
            'account': self.default_account,
            'user': self.default_user,
        }

        if not self.args.preference_file.parent.exists():
            self.args.preference_file.parent.mkdir(parents=True)

        with self.args.preference_file.open('w') as configfile:
            self.preferences.write(configfile)

    def should_refresh_credentials(self, user, role, idp_id, sp_id, aws_account_id, parent_aws_account_id, duration):
        if not self.args.store_cache:
            return True
        if not self.previous_account_id:
            return True
        if not self.previous_parent_aws_account_id:
            return True
        if self.previous_idp_id != idp_id:
            return True
        if self.previous_sp_id != sp_id:
            return True
        # if self.previous_account_id != aws_account_id:
        #     return True
        if self.previous_role != role:
            return True
        if self.previous_user != user:
            return True
        if self.previous_parent_aws_account_id != parent_aws_account_id:
            return True

        saml_file = self.saml_cache_file(idp_id)
        if not saml_file.exists():
            return True

        elements = ET.XML(saml_file.read_text())
        if 'IssueInstant' not in elements.keys():
            saml_file_str = str(saml_file)
            raise KeyError(f'IssueInstant not found on {saml_file_str}')

        issue_instant = elements.get('IssueInstant')
        if not issue_instant:
            saml_file.unlink()
            return True
        try:
            issue_datetime = datetime.datetime.fromisoformat(issue_instant[:-1])
            expiration_datetime = issue_datetime + datetime.timedelta(seconds=duration) - datetime.timedelta(minutes=1)
        except BaseException:
            excp = IssueInstantException('Failed to parse issue instant')
            excp.issue_instant = issue_instant
            raise excp

        now = datetime.datetime.utcnow()

        return now > expiration_datetime

    def delete_password(self, user):
        try:
            keyring.delete_password(self._keyring_namespace, user)
        except:
            self.log.warning('Password deletion failed')

    def get_password(self, user):
        try:
            return keyring.get_password(self._keyring_namespace, user)
        except:
            self.log.warning('Password retrieval failed')

    def set_password(self, user, password):
        try:
            keyring.set_password(self._keyring_namespace, user, password)
        except:
            self.log.warning('Password assignment failed')

    def do_auth(self, profile, user, role, sso_region, idp_id, sp_id, aws_account_id,
                      parent_aws_account_id, duration):

        if not role:
            self.log.error(f'role not provided for client {profile}, skipping.')
            return False

        if not sso_region:
            self.log.error(f'sso_region or region not provided for client {profile}, skipping.')
            return False

        if not idp_id:
            self.log.error(f'idp_id not provided for client {profile}, skipping.')
            return False

        if not sp_id:
            self.log.error(f'sp_id not provided for client {profile}, skipping.')
            return False

        if not aws_account_id:
            self.log.error(f'aws_account_id not provided for client {profile}, skipping.')
            return False

        if not parent_aws_account_id:
            self.log.error(f'parent_aws_account_id not provided for client {profile}, skipping.')
            return False

        if not user:
            self.log.error(f'user not provided for client {profile}, skipping.')
            return False

        password = self.get_password(user)

        while password is None:
            password = getpass(f'Enter password for Google Account ({user}):\n')
            self.set_password(user, password)

        environ = deepcopy(os.environ)
        role_arn = f"arn:aws:iam::{parent_aws_account_id}:role/{role}"
        self.log.debug(f'Trying to assume role {role_arn} with google user {user}.')
        cli_args = []
        cli_args.extend(['--role-arn', role_arn])
        cli_args.extend(['--sp-id', sp_id])
        cli_args.extend(['--idp-id', idp_id])
        cli_args.extend(['--username', user])
        cli_args.extend(['--account', aws_account_id])
        cli_args.extend(['--duration', str(duration)])
        cli_args.extend(['--region', sso_region])
        cli_args.extend(['--keyring'])

        if not self.args.store_cache:
            cli_args.extend(['--no-cache'])

        if self.args.resolve_aliases:
            cli_args.extend(['--resolve-aliases'])

        cli_args.extend(['--profile', profile])

        try:
            aws_google_auth.exit_if_unsupported_python()

            args = aws_google_auth.parse_args(cli_args)

            config = aws_google_auth.resolve_config(args)
            aws_google_auth.process_auth(args, config)
            os.environ = environ
            return True
        except aws_google_auth.google.ExpectedGoogleException as excp:
            self.log.error(excp)
            os.environ = environ
            return False
        except KeyboardInterrupt:
            os.environ = environ
            exit('Interrupted by the user. Exiting.')
        except EndpointConnectionError as excp:
            os.environ = environ
            self.log.error(str(excp))
            return False
        except BaseException as excp:
            output = str(excp)
            os.environ = environ

            if 'bad request' in output.lower():
                self.log.error(f'Parameters provided for profile {profile} are wrong.')
            elif 'forbidden' in output.lower():
                self.log.error(f'Forbidden access to account {user}')
            else:
                self.log.exception(excp)

            return False

    def run_process(self, profile, user, role, region, aws_account_id, extra_parameters, duration, expand_vars=False):
        if not self.command:
            exit("No command have been provided.")

        orig_env = deepcopy(os.environ)

        os.environ['AWS_PROFILE'] = profile
        os.environ['AWS_ASSUMED_ROLE_ARN'] = f"arn:aws:iam::{aws_account_id}:role/{role}"
        os.environ['AWS_ROLE_SESSION_NAME'] = user
        os.environ['AWS_REGION_NAME'] = region
        os.environ['AWS_ACCOUNT_ID'] = aws_account_id
        os.environ['AWS_DEFAULT_DURATION'] = str(duration)

        command = deepcopy(self.command)
        command.extend(extra_parameters)

        if self.args.expandvars or expand_vars:
            command = [expandvars(x) for x in self.command]
            command.extend(extra_parameters)

        try:
            proc = subprocess.run(command,
                                  stdin=subprocess.PIPE,
                                  stdout=sys.stdout,
                                  stderr=sys.stderr,
                                  env=os.environ)
        except subprocess.CalledProcessError as e:
            self.log.error(e)
            os.environ = orig_env
        except FileNotFoundError as err:
            os.environ = orig_env
            self.log.error(f'Command "{err.filename}" not found')
        except KeyboardInterrupt:
            os.environ = orig_env
            exit('Interrupted by the user. Exiting.')
        except BaseException as e:
            self.log.exception(e)
        os.environ = orig_env
        return proc.returncode

    def iterate_clients(self):


        return_codes = []
        for client in self.clients:
            role = self.args.gaws_content.get(client, 'role_name', fallback=self.default_role)
            regions = self.args.gaws_content.get(client, 'region', fallback=None)
            sso_region = self.args.gaws_content.get(client, 'sso_region', fallback=None) or self.default_sso_region
            idp_id = self.args.gaws_content.get(client, 'idp_id', fallback=None) or self.default_idp_id
            sp_id = self.args.gaws_content.get(client, 'sp_id', fallback=None) or self.default_sp_id
            user = self.args.gaws_content.get(client, 'user', fallback=None) or self.default_user
            aws_account_id = self.args.gaws_content.get(client, 'aws_account_id', fallback=None)
            expand_vars = self.args.gaws_content.get(client, 'expand_vars', fallback='').lower() == 'true'
            parent_aws_account_id = self.args.gaws_content.get(client, 'parent_aws_account_id', fallback=self.default_account)
            if parent_aws_account_id and parent_aws_account_id.lower() == 'aws_account_id':
                parent_aws_account_id = aws_account_id
            duration = try_int(self.args.gaws_content.get(client, 'duration', fallback=self.default_duration))
            extra_parameters = self.args.gaws_content.get(client, 'extra_parameters', fallback='')
            extra_parameters = shlex.split(extra_parameters) if extra_parameters else []
            duration = duration if duration > 0 else AWS_DEFAULT_DURATION
            profile = 'default'

            if regions:
                regions = [x.strip() for x in shlex.split(regions.lower()) if x.strip()]
            else:
                regions = [self.default_region] if self.default_region else []

            sso_region = sso_region if is_valid_region(sso_region) else None

            if not sso_region and regions:
                sso_region = regions[0]

            if not is_valid_region(sso_region):
                self.log.error(f'{sso_region} is not a valid AWS region, skipping client.')
                continue

            if self.args.inject_profile:
                profile = client

            has_logged_in = False
            should_refresh = True

            try:
                should_refresh = self.should_refresh_credentials(user, role, idp_id, sp_id, aws_account_id, parent_aws_account_id, duration)
            except IssueInstantException as excp:
                self.log.error(f'Cannot parse issue instant {excp.issue_instant}')
            except BaseException as excp:
                self.log.exception(excp)
                continue

            if should_refresh:
                has_logged_in = self.do_auth(profile, user, role, sso_region, idp_id, sp_id, aws_account_id, parent_aws_account_id, duration)

            if not has_logged_in:
                self.log.error(f'We were not able to login on profile {client}')
                continue

            for region in regions:
                if not is_valid_region(region):
                    self.log.error(f'{region} is not a valid AWS region, skipping region.')
                    continue
                region_extra_parameters = self.args.gaws_content.get(client, f'{region}_extra_parameters', fallback='')
                region_extra_parameters = shlex.split(region_extra_parameters) if region_extra_parameters else []
                used_parameters = region_extra_parameters or extra_parameters
                return_code = self.run_process(profile, user, role, region, aws_account_id, used_parameters, duration, expand_vars=expand_vars)
                return_codes.append(return_code)

            self.previous_sp_id = sp_id
            self.previous_idp_id = idp_id
            self.previous_parent_aws_account_id = parent_aws_account_id
            self.previous_account_id = aws_account_id
            self.previous_user = user
            self.previous_role = role

        return all([bool(x) for x in return_codes])


def main():
    try:
        gl = GAWS()
        if not gl.command:
            return 'No command provided'
        return int(gl.iterate_clients())
    except KeyboardInterrupt:
        return 'Interrupted by the user. Exiting.'


if __name__ == '__main__':
    sys.exit(main())
